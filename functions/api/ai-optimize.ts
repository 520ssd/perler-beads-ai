export async function onRequestPost(context: any) {
  try {
    const body = await context.request.json();
    const { imageBase64, prompt } = body;

    if (!prompt) {
      return new Response(JSON.stringify({ error: '缺少 prompt 参数' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    const ak = context.env.VOLC_ACCESS_KEY_ID;
    const sk = context.env.VOLC_SECRET_ACCESS_KEY;

    if (!ak || !sk) {
      return new Response(JSON.stringify({ error: '未配置密钥' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    const cleanBase64 = imageBase64?.includes(',') ? imageBase64.split(',')[1] : (imageBase64 || '');
    const requestBody = JSON.stringify({
      req_key: 'jimeng_t2i_v40',
      binary_data_base64: [cleanBase64],
      prompt: prompt,
      scale: 0.5,
      force_single: true,
    });

    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const xDate = `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}T${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}Z`;
    const dateShort = xDate.substring(0, 8);

    const encoder = new TextEncoder();

    const bodyHashBuf = await crypto.subtle.digest('SHA-256', encoder.encode(requestBody));
    const bodyHash = Array.from(new Uint8Array(bodyHashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

    const canonicalQuery = 'Action=CVSync2AsyncSubmitTask&Version=2022-08-31';
    const canonicalHeaders = `host:visual.volcengineapi.com\nx-date:${xDate}\nx-volc-content-sha256:${bodyHash}\n`;
    const signedHeaders = 'host;x-date;x-volc-content-sha256';
    const canonicalRequest = `POST\n/\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaders}\n${bodyHash}`;

    const crHashBuf = await crypto.subtle.digest('SHA-256', encoder.encode(canonicalRequest));
    const crHash = Array.from(new Uint8Array(crHashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

    const credentialScope = `${dateShort}/cn-north-1/cv/request`;
    const stringToSign = `VOLC4-HMAC-SHA256\n${xDate}\n${credentialScope}\n${crHash}`;

    async function hmacSign(key: Uint8Array | string, data: string): Promise<Uint8Array> {
      const keyData = typeof key === 'string' ? encoder.encode(key) : key;
      const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const sig = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
      return new Uint8Array(sig);
    }

    const kDate = await hmacSign(sk, dateShort);
    const kRegion = await hmacSign(kDate, 'cn-north-1');
    const kService = await hmacSign(kRegion, 'cv');
    const kSigning = await hmacSign(kService, 'request');

    const sigBytes = await hmacSign(kSigning, stringToSign);
    const signature = Array.from(sigBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    const authorization = `VOLC4-HMAC-SHA256 Credential=${ak}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

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

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });

  } catch (error: any) {
    return new Response(JSON.stringify({ error: error.message, stack: error.stack }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }
}