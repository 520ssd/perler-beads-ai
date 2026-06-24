export const onRequestPost = async (context) => {
  try {
    const { request, env } = context;
    const body = await request.json();
    const { imageBase64, prompt } = body;

    // 验证参数
    if (!imageBase64 || !prompt) {
      return new Response(JSON.stringify({ error: 'Missing parameters' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 验证密钥
    const ak = env.VOLC_ACCESS_KEY_ID;
    const sk = env.VOLC_SECRET_ACCESS_KEY;
    if (!ak || !sk) {
      return new Response(JSON.stringify({ error: 'Missing credentials' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 准备请求体
    const cleanBase64 = imageBase64.includes(',') ? imageBase64.split(',')[1] : imageBase64;
    const requestBody = JSON.stringify({
      req_key: 'jimeng_t2i_v40',
      binary_data_base64: [cleanBase64],
      prompt: prompt,
      scale: 0.5,
      force_single: true,
    });

    // 生成时间戳
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, '0');
    const day = String(now.getUTCDate()).padStart(2, '0');
    const hours = String(now.getUTCHours()).padStart(2, '0');
    const minutes = String(now.getUTCMinutes()).padStart(2, '0');
    const seconds = String(now.getUTCSeconds()).padStart(2, '0');
    const xDate = year + month + day + 'T' + hours + minutes + seconds + 'Z';
    const dateShort = year + month + day;

    // 计算 body hash
    const encoder = new TextEncoder();
    const bodyBytes = encoder.encode(requestBody);
    const bodyHashBuffer = await crypto.subtle.digest('SHA-256', bodyBytes);
    const bodyHash = Array.from(new Uint8Array(bodyHashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // 构建规范请求
    const canonicalQuery = 'Action=CVSync2AsyncSubmitTask&Version=2022-08-31';
    const canonicalHeaders = 'host:visual.volcengineapi.com\nx-date:' + xDate + '\nx-volc-content-sha256:' + bodyHash + '\n';
    const signedHeaders = 'host;x-date;x-volc-content-sha256';
    const canonicalRequest = 'POST\n/\n' + canonicalQuery + '\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + bodyHash;

    // 计算 canonical request hash
    const crBytes = encoder.encode(canonicalRequest);
    const crHashBuffer = await crypto.subtle.digest('SHA-256', crBytes);
    const crHash = Array.from(new Uint8Array(crHashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // 构建待签名字符串
    const credentialScope = dateShort + '/cn-north-1/cv/request';
    const stringToSign = 'VOLC4-HMAC-SHA256\n' + xDate + '\n' + credentialScope + '\n' + crHash;

    // 计算签名密钥
    async function hmacSign(key, data) {
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        typeof key === 'string' ? encoder.encode(key) : key,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const signature = await crypto.subtle.sign('HMAC', cryptoKey, typeof data === 'string' ? encoder.encode(data) : data);
      return new Uint8Array(signature);
    }

    function bytesToHex(bytes) {
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    const kDate = await hmacSign(sk, dateShort);
    const kRegion = await hmacSign(kDate, 'cn-north-1');
    const kService = await hmacSign(kRegion, 'cv');
    const kSigning = await hmacSign(kService, 'request');

    // 计算签名
    const signatureBytes = await hmacSign(kSigning, stringToSign);
    const signature = bytesToHex(signatureBytes);

    // 构建 Authorization
    const authorization = 'VOLC4-HMAC-SHA256 Credential=' + ak + '/' + credentialScope + ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;

    // 发送请求
    const response = await fetch('https://visual.volcengineapi.com/?Action=CVSync2AsyncSubmitTask&Version=2022-08-31', {
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

    const responseText = await response.text();
    
    return new Response(JSON.stringify({
      status: response.status,
      response: JSON.parse(responseText),
      debug: {
        xDate,
        bodyHash,
        canonicalRequest,
        stringToSign,
        signature,
        authorization
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    return new Response(JSON.stringify({
      error: error.message || 'Unknown error'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};