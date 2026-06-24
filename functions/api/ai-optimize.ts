interface Env {
  VOLC_ACCESS_KEY_ID: string;
  VOLC_SECRET_ACCESS_KEY: string;
}

const VOLC_API_HOST = 'visual.volcengineapi.com';
const VOLC_API_REGION = 'cn-north-1';
const VOLC_API_SERVICE = 'cv';

function toHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmac(key: ArrayBuffer, data: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
}

async function sha256(data: string): Promise<string> {
  const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return toHex(new Uint8Array(hashBuf));
}

function getXDate(): string {
  const d = new Date();
  return [
    d.getUTCFullYear(),
    String(d.getUTCMonth() + 1).padStart(2, '0'),
    String(d.getUTCDate()).padStart(2, '0'),
    'T',
    String(d.getUTCHours()).padStart(2, '0'),
    String(d.getUTCMinutes()).padStart(2, '0'),
    String(d.getUTCSeconds()).padStart(2, '0'),
    'Z'
  ].join('');
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
  try {
    const { request, env } = context;
    
    // 验证环境变量
    if (!env.VOLC_ACCESS_KEY_ID || !env.VOLC_SECRET_ACCESS_KEY) {
      return new Response(JSON.stringify({ error: 'Missing credentials' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 解析请求
    const body = await request.json();
    const { imageBase64, prompt } = body;

    if (!imageBase64 || !prompt) {
      return new Response(JSON.stringify({ error: 'Missing imageBase64 or prompt' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 清理 base64
    const cleanBase64 = imageBase64.includes(',') ? imageBase64.split(',')[1] : imageBase64;

    // 请求体
    const requestBodyStr = JSON.stringify({
      req_key: 'jimeng_t2i_v40',
      binary_data_base64: [cleanBase64],
      prompt: prompt,
      scale: 0.5,
      force_single: true,
    });

    // 计算哈希
    const bodyHash = await sha256(requestBodyStr);
    const xDate = getXDate();
    const dateShort = xDate.substring(0, 8); // YYYYMMDD

    // 构建规范请求
    const canonicalQuery = 'Action=CVSync2AsyncSubmitTask&Version=2022-08-31';
    const canonicalHeaders = `host:${VOLC_API_HOST}\nx-date:${xDate}\nx-volc-content-sha256:${bodyHash}\n`;
    const signedHeaders = 'host;x-date;x-volc-content-sha256';

    const canonicalRequest = `POST\n/\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaders}\n${bodyHash}`;

    // 构建待签名字符串
    const credentialScope = `${dateShort}/${VOLC_API_REGION}/${VOLC_API_SERVICE}/request`;
    const stringToSign = `VOLC4-HMAC-SHA256\n${xDate}\n${credentialScope}\n${await sha256(canonicalRequest)}`;

    // 计算签名密钥
    const secretKey = new TextEncoder().encode(env.VOLC_SECRET_ACCESS_KEY);
    const kDate = await hmac(secretKey, dateShort);
    const kRegion = await hmac(kDate, VOLC_API_REGION);
    const kService = await hmac(kRegion, VOLC_API_SERVICE);
    const kSigning = await hmac(kService, 'request');

    // 计算签名
    const signature = toHex(new Uint8Array(await hmac(kSigning, stringToSign)));

    // 构建 Authorization
    const authorization = `VOLC4-HMAC-SHA256 Credential=${env.VOLC_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    // 发送请求到火山引擎
    const apiUrl = `https://${VOLC_API_HOST}/?${canonicalQuery}`;
    
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Host': VOLC_API_HOST,
        'X-Date': xDate,
        'Content-Type': 'application/json',
        'Authorization': authorization,
        'X-Volc-Content-Sha256': bodyHash,
      },
      body: requestBodyStr,
    });

    const responseText = await response.text();
    const responseData = JSON.parse(responseText);

    // 返回结果（包含调试信息）
    return new Response(JSON.stringify({
      success: response.ok && !responseData.ResponseMetadata?.Error,
      data: responseData,
      debug: {
        xDate,
        dateShort,
        bodyHash,
        canonicalRequest,
        stringToSign,
        signature,
        authorization,
        apiUrl,
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Error:', error);
    return new Response(JSON.stringify({
      error: 'Failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};