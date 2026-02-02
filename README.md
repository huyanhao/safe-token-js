# safe-token-js
1.Embed arbitrary data within the token; 2.Token encryption securing content against client/intermediary access or tampering; 3.Express-compatible middleware maintaining token transmission consistency.

【初始化】
const SafeToken = require('./utils/safe-token-js')
const safeToken = new SafeToken({
    keysUrl: process.env.KEYS_URL
})
//（默认配置，如maxAge、httpOnly等根据需要自行添加）
const tokenTransfer = require('./middlewares/token-transfer')
app.use(tokenTransfer({
    encoding: 'base64url',
    maxAge: process.env.SESSION_MAXAGE,
    ...
}, safeToken))

【使用】
1.单独使用（不使用cookie）：
生成：safeToken.create(anyData)
解析：safeToken.parse(token)

2.中间件调用（使用cookie）：
发送至客户端：res.token('tokenName', anyData)
从请求中接收：req.token('tokenName')
