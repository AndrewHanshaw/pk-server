const express = require('express');
const multer = require('multer');
const forge = require('node-forge');
const fs = require('fs');
const crypto = require('crypto');
const AdmZip = require('adm-zip');
const upload = multer({
  dest: '/tmp',
  limits: {fileSize: 20 * 1024 * 1024}  // 20MB limit
});
var router = express.Router();

// Create a write stream to the desired file
const logFile = fs.createWriteStream('/tmp/output.log', {flags: 'a'});
const logStdout = process.stdout;

// Override console.log to write to both the file and stdout
console.log = function(message) {
  logFile.write(`${new Date().toISOString()} - ${message}\n`);
  logStdout.write(`${message}\n`);
};

const verbose = true;

function resolveCerts(passTypeIdentifier) {
  const suffix = passTypeIdentifier.split('.').pop();
  const isNumberedVariant = /^\d+$/.test(suffix);
  const certKey = isNumberedVariant ? `PK_cert_${suffix}` : 'PK_cert';
  const pkKey = 'PK_key';
  if (verbose) console.log(`resolveCerts: key=${pkKey}, cert=${certKey} for ${passTypeIdentifier}`);
  return { privateKeyPem: process.env[pkKey] || null, certificatePem: process.env[certKey] || null };
}

router.post('/sign', upload.single('pkpass'), (req, res) => {
  if (verbose) console.log('Received a request to /sign');
  const passPath = req.file.path;
  if (verbose) console.log(`Uploaded file path: ${passPath}`);

  const zip = new AdmZip(passPath);
  if (verbose) console.log('Extracting contents from the zip file');

  const entries = zip.getEntries();
  const files = entries.map(entry => entry.entryName);

  // Extract passTypeIdentifier from pass.json
  const passJsonEntry = zip.getEntry('pass.json');
  if (!passJsonEntry) {
    fs.unlinkSync(passPath);
    return res.status(400).send('Invalid .pkpass: missing pass.json');
  }
  let passTypeIdentifier;
  try {
    const passJson = JSON.parse(passJsonEntry.getData().toString('utf8'));
    passTypeIdentifier = passJson.passTypeIdentifier;
  } catch (e) {
    fs.unlinkSync(passPath);
    return res.status(400).send('Invalid .pkpass: could not parse pass.json');
  }
  if (!passTypeIdentifier) {
    fs.unlinkSync(passPath);
    return res.status(400).send('Invalid .pkpass: pass.json is missing passTypeIdentifier');
  }
  if (verbose) console.log(`passTypeIdentifier: ${passTypeIdentifier}`);

  const manifest = {};

  files.forEach(file => {
    if (file !== 'manifest.json') {
      const data = zip.readFile(file);
      const hash = crypto.createHash('sha1').update(data).digest('hex');
      manifest[file] = hash;
    }
  });

  // Convert manifest to JSON string
  const manifestJson = JSON.stringify(manifest, null, 2)
                           .replace(/":/g, '" :');  // Add space before each key
  if (verbose) console.log('Generated manifest.json');

  try {
    // Load private key and certificate
    const { privateKeyPem, certificatePem } = resolveCerts(passTypeIdentifier);
    if (!privateKeyPem || !certificatePem) {
      fs.unlinkSync(passPath);
      return res.status(400).send(`No signing certificate configured for passTypeIdentifier: ${passTypeIdentifier}`);
    }
    const wwdrPem = process.env.WWDR_cert;

    // Convert PEM to Forge objects
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const certificate = forge.pki.certificateFromPem(certificatePem);
    const wwdrCert = forge.pki.certificateFromPem(wwdrPem);

    if (verbose) console.log('Signing the manifest');
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(manifestJson, 'utf8');
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

    p7.addCertificate(certificatePem);
    p7.addCertificate(wwdrCert);

    p7.sign({detached: true});

    // Create DER signature
    const signature = forge.asn1.toDer(p7.toAsn1()).getBytes();
    if (verbose) console.log('Signature created successfully');

    // Add signature to the zip
    zip.addFile('manifest.json', Buffer.from(manifestJson, 'utf8'));
    zip.addFile('signature', Buffer.from(signature, 'binary'));

    // Save the signed .pkpass
    const signedPass = `/tmp/signed_${req.file.originalname}`;
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

module.exports = router;
