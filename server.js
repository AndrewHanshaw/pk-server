const express = require('express');
const multer = require('multer');
const forge = require('node-forge');
const fs = require('fs');
const crypto = require('crypto');
const AdmZip = require('adm-zip');
const upload = multer({dest: 'uploads/'});
const app = express();

app.post('/sign', upload.single('pkpass'), (req, res) => {
  console.log('Received a request to /sign');
  const passPath = req.file.path;
  console.log(`Uploaded file path: ${passPath}`);

  const zip = new AdmZip(passPath);
  console.log('Extracting contents from the zip file');

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
  console.log('Generated manifest.json');

  try {
    // Load private key and certificate
    const privateKeyPem = fs.readFileSync('private-key.pem', 'utf8');
    const certificatePem = fs.readFileSync('cert.pem', 'utf8');
    const wwdrCertPem =
        fs.readFileSync('AppleWWDRCA.pem', 'utf8');  // Load WWDR cert as PEM

    // Convert PEM to Forge objects
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const certificate = forge.pki.certificateFromPem(certificatePem);
    const wwdrCert = forge.pki.certificateFromPem(wwdrCertPem);

    console.log('Signing the manifest');
    // Sign manifest
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(manifestJson, 'utf8');
    p7.addCertificate(certificate);
    p7.addCertificate(wwdrCert);  // Add WWDR certificate
    p7.addSigner({
      key: privateKey,
      certificate: certificate,
      digestAlgorithm: forge.pki.oids.sha1,
    });

    p7.sign();

    // Create DER signature
    const signature = forge.asn1.toDer(p7.toAsn1()).getBytes();
    console.log('Signature created successfully');

    // Add signature to the zip
    zip.addFile('manifest.json', Buffer.from(manifestJson, 'utf8'));
    zip.addFile('signature', Buffer.from(signature, 'binary'));

    // Save the signed .pkpass
    const signedPass = `signed_${req.file.originalname}`;
    zip.writeZip(signedPass);
    console.log(`Signed .pkpass saved as ${signedPass}`);

    // Send back the signed pass
    res.download(signedPass, () => {
      fs.unlinkSync(passPath);
      fs.unlinkSync(signedPass);  // Clean up
      console.log('Temporary files cleaned up');
    });
  } catch (error) {
    console.error('Error during signing process:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
