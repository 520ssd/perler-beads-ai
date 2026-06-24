interface Env {
  VOLC_ACCESS_KEY_ID: string;
  VOLC_SECRET_ACCESS_KEY: string;
}

const VOLC_API_HOST = 'visual.volcengineapi.com';
const VOLC_API_REGION = 'cn-north-1';
const VOLC_API_SERVICE = 'cv';

const encoder = new TextEncoder();

function toHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmac(key: Uint8Array, data: string): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
  return new Uint8Array(sig);
}

async function sha256(data: string): Promise<string> {
  const hashBuf = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return toHex(new Uint8Array(hashBuf));
}

function getDateTimeNow(): string {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  const day = String(now.getUTCDate()).padStart(2, '0');
  const hours = String(now.getUTCHours()).padStart(2, '0');
  const minutes = String(now.getUTCMinutes()).padStart(2, '0');
  const seconds = String(now.getUTCSeconds()).padStart(2, '0');
  return `${year}${month}${day}T${hours}${minutes}${seconds}Z`;
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
  try {
    const { request, env } = context;
    const { imageBase64, prompt } = await request.json();

    if (!imageBase64 || !prompt) {
      return Response.json({ error: 'Missing parameters' }, { status: 400 });
    }

    // 调试：检查密钥格式
    console.log('AK length:', env.VOLC_ACCESS_KEY_ID?.length);
    console.log('SK length:', env.VOLC_SECRET_ACCESS_KEY?.length);
    console.log('AK first/last char:', env.VOLC_ACCESS_KEY_ID?.[0], env.VOLC_ACCESS_KEY_ID?.slice(-1));
    console.log('SK contains newline:', env.VOLC_SECRET_ACCESS_KEY?.includes('\n'));
    console.log('SK contains space:', env.VOLC_SECRET_ACCESS_KEY?.includes(' '));

    const base64Data = imageBase64.includes(',') ? imageBase64.split(',')[1] : imageBase64;
    const requestBody = JSON.stringify({
      req_key: 'jimeng_t2i_v40',
      binary_data_base64: [base64Data],
      prompt: prompt,
      scale: 0.5,
      force_single: true,
    });

    const bodyHash = await sha256(requestBody);
    const xDate = getDateTimeNow();
    const date = xDate.split('T')[0];

    // 构建规范请求 - 注意换行符位置
    const canonicalQueryString = 'Action=CVSync2AsyncSubmitTask&Version=2022-08-31';
    
    // 注意：canonicalHeaders 最后没有额外的换行符
    const canonicalHeaders = [
      `host:${VOLC_API_HOST}`,
      `x-date:${xDate}`,
      `x-volc-content-sha256:${bodyHash}`
    ].join('\n');
    
    const signedHeaders = 'host;x-date;x-volc-content-sha256';
    
    const canonicalRequest = [
      'POST',
      '/',
      canonicalQueryString,
      canonicalHeaders + '\n',  // 关键：headers后面需要两个换行
      signedHeaders,
      bodyHash
    ].join('\n');

    console.log('=== CANONICAL REQUEST ===');
    console.log(canonicalRequest);
    console.log('=== END CANONICAL REQUEST ===');

    const canonicalRequestHash = await sha256(canonicalRequest);
    console.log('Canonical Request Hash:', canonicalRequestHash);

    const credentialScope = `${date}/${VOLC_API_REGION}/${VOLC_API_SERVICE}/request`;
    const stringToSign = [
      'VOLC4-HMAC-SHA256',
      xDate,
      credentialScope,
      canonicalRequestHash
    ].join('\n');

    console.log('=== STRING TO SIGN ===');
    console.log(stringToSign);
    console.log('=== END STRING TO SIGN ===');

    // 计算签名密钥
    const kSecret = encoder.encode(env.VOLC_SECRET_ACCESS_KEY);
    const kDate = await hmac(kSecret, date);
    console.log('kDate:', toHex(kDate));
    
    const kRegion = await hmac(kDate, VOLC_API_REGION);
    console.log('kRegion:', toHex(kRegion));
    
    const kService = await hmac(kRegion, VOLC_API_SERVICE);
    console.log('kService:', toHex(kService));
    
    const kSigning = await hmac(kService, 'request');
    console.log('kSigning:', toHex(kSigning));
    
    const signature = toHex(await hmac(kSigning, stringToSign));
    console.log('Signature:', signature);

    const authorization = `VOLC4-HMAC-SHA256 Credential=${env.VOLC_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    console.log('Authorization:', authorization);

    // 发送请求
    const response = await fetch(
      `https://${VOLC_API_HOST}/?${canonicalQueryString}`,
      {
        method: 'POST',
        headers: {
          'Host': VOLC_API_HOST,
          'X-Date': xDate,
          'Content-Type': 'application/json',
          'Authorization': authorization,
          'X-Volc-Content-Sha256': bodyHash,
        },
        body: requestBody,
      }
    );

    const responseText = await response.text();
    console.log('Response:', response.status, responseText);

    return Response.json({
      success: response.ok,
      debug: {
        xDate,
        bodyHash,
        canonicalRequest,
        stringToSign,
        signature,
        authorization,
        responseStatus: response.status,
        responseText: responseText.substring(0, 500)
      }
    });

  } catch (error) {
    console.error('Error:', error);
    return Response.json(
      { error: 'Failed', message: error instanceof Error ? error.message : 'Unknown' },
      { status: 500 }
    );
  }
};