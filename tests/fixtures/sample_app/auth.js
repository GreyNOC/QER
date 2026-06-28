const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
const insecureHeader = { "alg": "none" };
const legacy = crypto.createHash('md5').update(data).digest('hex');
const desCipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
