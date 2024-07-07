const express = require('express')
const multer = require('multer')
const fs = require('fs')
const pkijs = require('pkijs')

pkijs.setEngine('crypto', require('crypto'), require('crypto').subtle)

const app = express()
const port = 1337

const upload = multer({ storage: multer.memoryStorage() })

const DUCTFRootCA_PEM = fs.readFileSync('./root.crt')
const DUCTFRootCA = pkijs.Certificate.fromBER(Buffer.from(DUCTFRootCA_PEM.toString().slice(28, -27).replace('\n', ''), 'base64'))
const TO_SIGN = 'I can forge a signed message!'
const FLAG = process.env.FLAG || 'DUCTF{testflag}'

async function verify(file_data) {
    const cms = pkijs.ContentInfo.fromBER(file_data)

    if(cms.contentType !== pkijs.ContentInfo.SIGNED_DATA) {
        return 'Invalid content type'
    }
    const signedData = new pkijs.SignedData({ schema: cms.content })
    const data = new TextDecoder().decode(signedData.encapContentInfo.eContent.valueBlock.valueHexView)
    if(data != TO_SIGN) {
        return 'Invalid data'
    }

    const verifParams = {
        signer: 0,
        trustedCerts: [DUCTFRootCA],
        checkChain: true
    }

    return await signedData.verify(verifParams).catch((e) => e)
}

app.post('/upload', upload.single('cms'), async (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded.')
  }

  const file = req.file
  let result = false
  try {
    result = await verify(file.buffer)
  } catch(e) {
    result = e
  }

  if (result === true) {
    res.status(200).send(FLAG)
  } else if(result === false) {
    res.status(400).send('Verification failed.')
  } else {
    res.status(400).send(result.toString())
}
})

app.get('/', (_, res) => {
    res.type('text')
    res.send('Can you forge a message signed from our top secret root CA?\n\n' + DUCTFRootCA_PEM)
})

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
})
