const express = require('express');
const multer = require('multer');
const forge = require('node-forge');
const fs = require('fs');
const crypto = require('crypto');
const AdmZip = require('adm-zip');
const minimist = require('minimist');
const upload = multer({dest: 'uploads/'});
var router = express.Router();

const verbose = true;

router.post('/sign', upload.single('pkpass'), (req, res) => {
  if (verbose) console.log('Received a request to /sign');
  const passPath = req.file.path;
  if (verbose) console.log(`Uploaded file path: ${passPath}`);

  const zip = new AdmZip(passPath);
  if (verbose) console.log('Extracting contents from the zip file');

  const files = zip.getEntries().map(entry => entry.entryName);
  const manifest = {};

  files.forEach(file => {
    if (file !== 'manifest.json') {
      const data = zip.readFile(file);
      const hash = crypto.createHash('sha1').update(data).digest('hex');
      manifest[file] = hash;
    }
  });

  // Convert manifest to JSON string
  const manifestJson = JSON.stringify(manifest, null, 2);
  if (verbose) console.log('Generated manifest.json');

  try {
    // Load private key and certificate
    const privateKeyPem = process.env.PK_key;
    const certificatePem = process.env.PK_cert;

    // Convert PEM to Forge objects
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const certificate = forge.pki.certificateFromPem(certificatePem);

    if (verbose) console.log('Signing the manifest');
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(manifestJson, 'utf8');
    p7.addCertificate(certificate);
    p7.addSigner({
      key: privateKey,
      certificate: certificate,
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        {type: forge.pki.oids.contentType, value: forge.pki.oids.data},
        {type: forge.pki.oids.messageDigest},
        {type: forge.pki.oids.signingTime, value: new Date()}
      ]
    });

    p7.sign({detached: true});

    // Create DER signature
    const signature = forge.asn1.toDer(p7.toAsn1()).getBytes();
    if (verbose) console.log('Signature created successfully');

    // Add signature to the zip
    zip.addFile('manifest.json', Buffer.from(manifestJson, 'utf8'));
    zip.addFile('signature', Buffer.from(signature, 'binary'));

    // Save the signed .pkpass
    const signedPass = `signed_${req.file.originalname}`;
    zip.writeZip(signedPass);
    if (verbose) console.log(`Signed .pkpass saved as ${signedPass}`);

    // Send back the signed pass
    res.download(signedPass, () => {
      fs.unlinkSync(passPath);
      fs.unlinkSync(signedPass);  // Clean up
      if (verbose) console.log('Temporary files cleaned up');
    });
  } catch (error) {
    console.error('Error during signing process:', error);
    res.status(500).send('Internal Server Error');
  }
});

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', {title: 'Express'});
});

module.exports = router;
