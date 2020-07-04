const crypto = require('crypto')
const base32 = require('hi-base32')
const { prompt } = require('enquirer')
const fs = require('fs')

function generateSecret (length = 20) {
  const randomBuffer = crypto.randomBytes(length)
  return base32.encode(randomBuffer).replace(/=/g, '')
}

function generateHOTP (secret, counter) {
  const decodedSecret = base32.decode.asBytes(secret)
  const buffer = Buffer.alloc(8)
  for (let i = 0; i < 8; i++) {
    buffer[7 - i] = counter & 0xff
    counter = counter >> 8
  }

  // Step 1: Generate an HMAC-SHA-1 value
  const hmac = crypto.createHmac('sha1', Buffer.from(decodedSecret))
  hmac.update(buffer)
  const hmacResult = hmac.digest()

  // Step 2: Generate a 4-byte string (Dynamic Truncation)
  const code = dynamicTruncationFn(hmacResult)

  // Step 3: Compute an HOTP value
  return code % 10 ** 6
}

function dynamicTruncationFn (hmacValue) {
  const offset = hmacValue[hmacValue.length - 1] & 0xf

  return (
    ((hmacValue[offset] & 0x7f) << 24) |
      ((hmacValue[offset + 1] & 0xff) << 16) |
      ((hmacValue[offset + 2] & 0xff) << 8) |
      (hmacValue[offset + 3] & 0xff)
  )
}

function generateTOTP (secret, window = 0) {
  const counter = Math.floor(Date.now() / 30000)
  return generateHOTP(secret, counter + window)
}

function verifyTOTP (token, secret, window = 1) {
  if (Math.abs(+window) > 10) {
    console.error('Window size is too large')
    return false
  }

  for (let errorWindow = -window; errorWindow <= +window; errorWindow++) {
    const totp = generateTOTP(secret, errorWindow)
    if (token === totp) {
      return true
    }
  }

  return false
}

const secret = generateSecret()
console.log(secret)
const qrURL = `otpauth://totp/Test App:yourusername?secret=${secret}&issuer=Test App`
const page = `
<div id="qrcode"></div>
<script src="qrcode.min.js"></script>
<script type="text/javascript">
new QRCode(document.getElementById("qrcode"), "${qrURL}");
</script>
`
fs.writeFile('qr.html', page, function (err) {
  if (err) throw err
})
prompt({
  type: 'input',
  name: 'totp',
  message: 'What is your otp?'
})
  .then(response => {
    console.log(verifyTOTP(+response.totp, secret))
  })
