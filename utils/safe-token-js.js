const fs = require('node:fs')
const v8 = require('node:v8')
const crypto = require('node:crypto')

class SafeToken {
    static ALLOW_ENCODING = new Set(['latin1', 'hex', 'base64', 'base64url'])
    static DEFAULT_ENCODING = 'hex'
    static SEPARATOR = '.'

    static key(length = 32) {
        return crypto.randomBytes(length)
    }

    #secretKey
    #publicKey
    #privateKey

    constructor(options = {}) {
        const { keysUrl = './ST-keys' } = options
        if (!fs.existsSync(keysUrl)) fs.mkdirSync(keysUrl)

        const secretKeyUrl = keysUrl + '/secret'
        const publicKeyUrl = keysUrl + '/public.der'
        const privateKeyUrl = keysUrl + '/private.der'

        if (!fs.existsSync(secretKeyUrl)) {
            const secretKey = SafeToken.key()
            fs.writeFileSync(secretKeyUrl, secretKey)
        }
        if (!fs.existsSync(publicKeyUrl) || !fs.existsSync(privateKeyUrl)) {
            const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
                publicKeyEncoding: {
                    format: 'der',
                    type: 'spki',
                },
                privateKeyEncoding: {
                    format: 'der',
                    type: 'pkcs8',
                },
            })
            fs.writeFileSync(publicKeyUrl, publicKey)
            fs.writeFileSync(privateKeyUrl, privateKey)
        }

        this.#secretKey = fs.readFileSync(secretKeyUrl)
        this.#publicKey = crypto.createPublicKey({
            key: fs.readFileSync(publicKeyUrl),
            format: 'der',
            type: 'spki',
        })
        this.#privateKey = crypto.createPrivateKey({
            key: fs.readFileSync(privateKeyUrl),
            format: 'der',
            type: 'pkcs8',
        })
    }

    /**
     * @param {*} data
     * @param {String} encoding
     * @returns {String}
     */
    create(data, encoding = SafeToken.DEFAULT_ENCODING) {
        if (!SafeToken.ALLOW_ENCODING.has(encoding)) throw new TypeError(`Invalid argument(encoding): ${encoding}. Allowed: ${[...SafeToken.ALLOW_ENCODING]}`)

        // const _data = JSON.stringify(data)
        const _data = v8.serialize(data)

        const nonce = crypto.randomBytes(12)
        const cipher = crypto.createCipheriv('aes-256-gcm', this.#secretKey, nonce)
        const encrypted = Buffer.concat([cipher.update(_data), cipher.final()])
        const tag = cipher.getAuthTag()
        const payload = Buffer.concat([nonce, tag, encrypted]).toString(encoding)

        const besigned = Buffer.from(encoding + payload, 'utf8')
        const signature = crypto.sign(null, besigned, this.#privateKey).toString(encoding)

        return [
            encoding,
            payload,
            signature
        ].join(SafeToken.SEPARATOR)
    }
    /**
     * @param {String} token
     * @returns {*}
     */
    parse(token) {
        if (typeof token !== 'string') return null

        const parts = token.split(SafeToken.SEPARATOR, 3)
        if (parts.length < 3 || parts.includes('')) return null
        const [encoding, payload, signature] = parts
        if (!SafeToken.ALLOW_ENCODING.has(encoding)) return null

        const besigned = Buffer.from(encoding + payload, 'utf8')
        const _signature = Buffer.from(signature, encoding)
        if (!crypto.verify(null, besigned, this.#publicKey, _signature)) return null

        const _payload = Buffer.from(payload, encoding)
        if (_payload.length <= 12 + 16) return null

        const nonce = _payload.subarray(0, 12)
        const tag = _payload.subarray(12, 12 + 16)
        const data = _payload.subarray(12 + 16)
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.#secretKey, nonce).setAuthTag(tag)
        try {
            const decrypted = Buffer.concat([decipher.update(data), decipher.final()])
            // return JSON.parse(decrypted)
            return v8.deserialize(decrypted)
        } catch {
            return null
        }
    }
    key(length = 32, encoding = SafeToken.DEFAULT_ENCODING) {
        if (!SafeToken.ALLOW_ENCODING.has(encoding)) throw new TypeError(`Invalid argument(encoding): ${encoding}. Allowed: ${[...SafeToken.ALLOW_ENCODING]}`)
        return crypto.randomBytes(length).toString(encoding)
    }
    hash(data, encoding = SafeToken.DEFAULT_ENCODING) {
        if (!SafeToken.ALLOW_ENCODING.has(encoding)) throw new TypeError(`Invalid argument(encoding): ${encoding}. Allowed: ${[...SafeToken.ALLOW_ENCODING]}`)

        // const _data = JSON.stringify(data)
        const _data = v8.serialize(data)

        const hash = crypto.createHash("sha256")
        hash.update(_data)
        return hash.digest().toString(encoding)
    }
    hmac(data, secret = this.#secretKey, encoding = SafeToken.DEFAULT_ENCODING) {
        if (typeof secret !== 'string' && !Buffer.isBuffer(secret)) throw new TypeError(`Invalid argument(secret): ${secret}. Allowed: String, Buffer`)
        if (!SafeToken.ALLOW_ENCODING.has(encoding)) throw new TypeError(`Invalid argument(encoding): ${encoding}. Allowed: ${[...SafeToken.ALLOW_ENCODING]}`)

        // const _data = JSON.stringify(data)
        const _data = v8.serialize(data)

        const hmac = crypto.createHmac("sha256", secret)
        hmac.update(_data)
        return hmac.digest().toString(encoding)
    }
}

module.exports = SafeToken

/*

【初始化】
const SafeToken = require('../your-path/safe-token')
const safeToken = new SafeToken({
    keysUrl: process.env.KEYS_URL,
})
注：实例初始化后会在指定目录生成密钥文件夹，其中private为私钥，注意安全保存，严禁泄露；public为公钥，可随意分发；secret为AES加密密钥，传输前必须使用对方公钥加密

【使用】
创建token：safeToken.create(data, encoding)
data(any): 自定义数据
encoding(string)：编码方式，默认hex；
返回值样例：hex
.9d5c099251ee87bb75029f50cd7751737ba440f4a21673f2ae1d333422e20d1bcb565fffdddc1a58d036efafdcc6f71b999cf76276bb7106d2c155b78f8b6a13
.b6ab8ada56e21fce44151104fb09a2e45c52ee1c5fec860fd02df352ed5fd5ca6746d36b8e67ce657aa87700ba33f209fe68ac0291f27bcf72b7ad6a25f40b0e

解析token：safeToken.parse(data)
data:create()函数生成的token
返回值样例：{
    a: 0,
    b: '',
    c: null,
    d: undefined,
    e: 11223344556677889900n
}

 */
