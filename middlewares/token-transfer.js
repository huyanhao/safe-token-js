module.exports = (options = {}, safeToken) => {
    if (!safeToken || safeToken.constructor.name !== 'SafeToken') {
        safeToken = null
        console.log('Token Transfer: Simple Mode')
    }
    const {
        encoding = 'hex',
        maxAge = 300,
        httpOnly = true,
        secure = true,
        partitioned = true,
        sameSite = 'strict',
        priority = 'high',
    } = options

    const nameRegExp = /^[^;=]*$/
    const valueRegExp = /^[^;]*$/
    const domainRegExp = /^[a-zA-Z\d]+([-\.]{1}[a-zA-Z\d]+)*\.[a-zA-Z]{2,}$/
    const pathRegExp = /^(\/{1}[^/;]+)+$/
    const maxAgeRegExp = /^\d+$/
    const encodingVerify = (value) => {
        const list = ['latin1', 'hex', 'base64', 'base64url']
        if (list.includes(value)) return value
        throw new TypeError(`Invalid argument(encoding): ${value}. Allowed: ${list.join(', ')}`)
    }
    const nameVerify = (value) => {
        if (typeof value === 'string' && nameRegExp.test(value)) return value
        throw new TypeError(`Invalid argument(name): ${value}.`)
    }
    const valueVerify = (value) => {
        if (typeof value === 'string' && valueRegExp.test(value)) return value
        throw new TypeError(`Invalid argument(value): ${value}.`)
    }
    const domainVerify = (value) => {
        if (domainRegExp.test(value)) return value
        throw new TypeError(`Invalid argument(domain): ${value}.`)
    }
    const pathVerify = (value) => {
        if (pathRegExp.test(value)) return value
        throw new TypeError(`Invalid argument(path): ${value}.`)
    }
    const maxAgeVerify = (value) => {
        if (maxAgeRegExp.test(value) || Number.isInteger(value)) return value
        throw new TypeError(`Invalid argument(maxAge): ${value}. Allowed: pure number string, integer`)
    }
    const sameSiteVerify = (value) => {
        const list = ['strict', 'lax', 'none']
        if (list.includes(value)) return value
        throw new TypeError(`Invalid argument(sameSite): ${value}. Allowed: ${list.join(', ')}`)
    }
    const priorityVerify = (value) => {
        const list = ['low', 'medium', 'high']
        if (list.includes(value)) return value
        throw new TypeError(`Invalid argument(priority): ${value}. Allowed: ${list.join(', ')}`)
    }

    encodingVerify(encoding)
    maxAgeVerify(maxAge)
    sameSiteVerify(sameSite)
    priorityVerify(priority)

    return (req, res, next) => {
        let cookieParsed = false
        const cookies = new Map()

        req.token = (name) => {
            const tokenParse = (name) => {
                if (typeof name === 'string') {
                    const token = cookies.get(name)
                    if (token) return safeToken.parse(token)
                }
                console.log(`Nonexistence: ${name}, Current cookies: ${[...cookies.keys()]}`)
                return null
            }
            if (cookieParsed) return tokenParse(name)

            const cookie = req.headers['cookie']
            if (cookie) {
                const parts = cookie.split(';')
                
                for(const item of parts) {
                    const index = item.indexOf('=')
                    if (index === -1) {
                        cookies.set('', item.trim())
                        continue
                    }
                    const key = item.slice(0, index).trim()
                    const value = item.slice(index + 1).trim()
                    cookies.set(key, value)
                }
            }
            cookieParsed = true

            return tokenParse(name)
        }
        
        res.token = (name, value, options = {}) => {
            const cookies = res.getHeader('Set-Cookie') || []
            const cookie = [`${nameVerify(name)}=${safeToken ? safeToken.create(value, encoding) : valueVerify(value)}`]

            if (options.domain) cookie.push(`Domain=${domainVerify(options.domain)}`)

            if (options.path) {
                cookie.push(`Path=${pathVerify(options.path)}`)
            } else {
                cookie.push(`Path=${req.path}`)
            }

            if (options.maxAge) {
                cookie.push(`Max-Age=${maxAgeVerify(options.maxAge)}`)
            } else if(maxAge) {
                cookie.push(`Max-Age=${maxAge}`)
            }

            if (options.httpOnly ?? httpOnly) cookie.push('HttpOnly')

            if (options.secure ?? secure) cookie.push('Secure')

            if (options.partitioned ?? partitioned) cookie.push('Partitioned')

            if (options.sameSite) {
                cookie.push(`SameSite=${sameSiteVerify(options.sameSite)}`)
            } else {
                cookie.push(`SameSite=${sameSite}`)
            }
            
            if (options.priority) {
                cookie.push(`Priority=${priorityVerify(options.priority)}`)
            } else {
                cookie.push(`Priority=${priority}`)
            }

            cookies.push(cookie.join('; '))
            res.setHeader('Set-Cookie', cookies)
        }
        
        next()
    }
}

/*

【初始化】
const tokenTransfer = require('./middlewares/token-transfer')
app.use(tokenTransfer({
    encoding: 'base64url',
    maxAge: process.env.SESSION_MAXAGE
}, safeToken))
注：使用本中间件需传入SafeToken实例，创建实例详见safe-token-js工具说明。

【使用】
发送token：res.token('token', data)
接收token：req.token('token')
data(any): 自定义数据。如果未传入SafeToken实例，则data必须为string类型
返回值样例：{
    a: 0,
    b: '',
    c: null,
    d: undefined,
    e: 11223344556677889900n
}


 */

