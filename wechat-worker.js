// Cloudflare Worker for WeChat Official Account Auto Reply (ES Modules)
// 当微信公众号收到任何消息时，自动回复"已收到"

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 处理微信公众号服务器配置验证
    if (request.method === 'GET') {
      return handleWeChatVerification(request, env);
    }

    // 处理微信消息
    if (request.method === 'POST' && url.pathname === '/') {
      return handleWeChatMessage(request, env);
    }

    return new Response('Not Found', { status: 404 });
  },
};

// 处理微信服务器验证
async function handleWeChatVerification(request, env) {
  const url = new URL(request.url);
  const signature = url.searchParams.get('signature');
  const timestamp = url.searchParams.get('timestamp');
  const nonce = url.searchParams.get('nonce');
  const echostr = url.searchParams.get('echostr');

  const token = env.WX_TOKEN; // ES Modules 中通过 env 读取

  if (!signature || !timestamp || !nonce || !echostr || !token) {
    return new Response('Invalid parameters', { status: 400 });
  }

  // 验证签名
  const tmpStr = [token, timestamp, nonce].sort().join('');
  const encoder = new TextEncoder();
  const data = encoder.encode(tmpStr);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  if (hashHex === signature) {
    return new Response(echostr);
  } else {
    return new Response('Invalid signature', { status: 403 });
  }
}

// 处理微信消息
async function handleWeChatMessage(request, env) {
  try {
    const xmlText = await request.text();
    console.log('Received WeChat message:', xmlText);

    const toUserName = extractXmlValue(xmlText, 'ToUserName');
    const fromUserName = extractXmlValue(xmlText, 'FromUserName');

    if (!toUserName || !fromUserName) {
      throw new Error('Invalid message format');
    }

    const replyXml = generateReplyXml(fromUserName, toUserName, '已收到v1.2');

    return new Response(replyXml, {
      headers: { 'Content-Type': 'application/xml' },
    });
  } catch (error) {
    console.error('Error handling WeChat message:', error);
    return new Response('Error processing message', { status: 500 });
  }
}

// 工具函数
function extractXmlValue(xml, tagName) {
  const regex = new RegExp(`<${tagName}><!\\[CDATA\\[(.*?)\\]\\]></${tagName}>`, 'i');
  const match = xml.match(regex);
  return match ? match[1] : null;
}

function generateReplyXml(toUserName, fromUserName, content) {
  const timestamp = Math.floor(Date.now() / 1000);
  return `<xml>
  <ToUserName><![CDATA[${toUserName}]]></ToUserName>
  <FromUserName><![CDATA[${fromUserName}]]></FromUserName>
  <CreateTime>${timestamp}</CreateTime>
  <MsgType><![CDATA[text]]></MsgType>
  <Content><![CDATA[${content}]]></Content>
</xml>`;
}
