import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { imageBase64, prompt } = body;

    if (!prompt) {
      return NextResponse.json({ error: '缺少 prompt 参数' }, { status: 400 });
    }

    const ak = process.env.VOLC_ACCESS_KEY_ID;
    const sk = process.env.VOLC_SECRET_ACCESS_KEY;

    if (!ak || !sk) {
      return NextResponse.json({ error: '未配置火山引擎密钥' }, { status: 500 });
    }

    const cleanBase64 = imageBase64?.includes(',') ? imageBase64.split(',')[1] : (imageBase64 || '');
    const requestBody = JSON.stringify({
      req_key: 'jimeng_t2i_v40',
      binary_data_base64: [cleanBase64],
      prompt: prompt,
      scale: 0.5,
      force_single: true,
    });

    // 时间戳
    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const xDate = `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}T${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}Z`;
    const dateShort = xDate.substring(0, 8);

    const encoder = new TextEncoder();

    // Body hash
    const bodyHashBuf = await crypto.subtle.digest('SHA-256', encoder.encode(requestBody));
    const bodyHash = Array.from(new Uint8Array(bodyHashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

    // Canonical Request
    const canonicalQuery = 'Action=CVSync2AsyncSubmitTask&Version=2022-08-31';
    const canonicalHeaders = `host:visual.volcengineapi.com\nx-date:${xDate}\nx-volc-content-sha256:${bodyHash}\n`;
    const signedHeaders = 'host;x-date;x-volc-content-sha256';
    const canonicalRequest = `POST\n/\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaders}\n${bodyHash}`;

    // String to Sign
    const crHashBuf = await crypto.subtle.digest('SHA-256', encoder.encode(canonicalRequest));
    const crHash = Array.from(new Uint8Array(crHashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

    const credentialScope = `${dateShort}/cn-north-1/cv/request`;
    const stringToSign = `VOLC4-HMAC-SHA256\n${xDate}\n${credentialScope}\n${crHash}`;

    // HMAC
    async function hmacSign(key: Uint8Array | string, data: string): Promise<Uint8Array> {
      const keyData = typeof key === 'string' ? encoder.encode(key) : key;
      const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const sig = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
      return new Uint8Array(sig);
    }

    // 签名密钥
    const kDate = await hmacSign(sk, dateShort);
    const kRegion = await hmacSign(kDate, 'cn-north-1');
    const kService = await hmacSign(kRegion, 'cv');
    const kSigning = await hmacSign(kService, 'request');

    // 签名
    const sigBytes = await hmacSign(kSigning, stringToSign);
    const signature = Array.from(sigBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    const authorization = `VOLC4-HMAC-SHA256 Credential=${ak}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    // 请求火山引擎
    const response = await fetch(`https://visual.volcengineapi.com/?${canonicalQuery}`, {
      method: 'POST',
      headers: {
        'Host': 'visual.volcengineapi.com',
        'X-Date': xDate,
        'Content-Type': 'application/json',
        'Authorization': authorization,
        'X-Volc-Content-Sha256': bodyHash,
      },
      body: requestBody,
    });

    const result = await response.json();
    
    return NextResponse.json(result);

  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}