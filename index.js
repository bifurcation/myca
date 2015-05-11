"use strict";

/*** Constants ***/

var KEY_SIZE = 2048;

var FILE_ROOT_KEY = "root.key.pem";
var FILE_ROOT_CERT = "root.cert.pem";

var CLASS_PROGRESS = "statusProgress";
var CLASS_DONE = "statusDone";
var CLASS_ERROR = "statusError";


/*** State ***/

var gRootKeyPair;
var gRootCert;
var gRootKeyPEM;
var gRootCertPEM;


/*** Utilities ***/

function updateStatus(target, text, style) {
  $("#" + target + "Status").text(text)
  if (style) {
    $("#" + target + "Status").removeClass().addClass(style);
  }
}

function saveFile(filename, text) {
  if (!text) {
    console.log("Failed to download empty file for " + filename);
    return;
  }
  var blob = new Blob([text], {type: "application/x-pem-file"});
  saveAs(blob, filename);
}


/*** Root generation ***/

function makeRoot() {
  var tag = "makeRoot";

  /* Build the name from the entered name */
  var enteredName = $("#rootName").val();
  if (!enteredName) {
    updateStatus(tag, "(enter a name)", CLASS_ERROR);
    return;
  }
  var name = [{
    name: "commonName",
    value: enteredName 
  }];

  /* Generate a key pair */
  updateStatus(tag, "(generating key)", CLASS_PROGRESS);
  gRootKeyPair = forge.pki.rsa.generateKeyPair(KEY_SIZE);

  /* Create a self-signed certificate */
  gRootCert = forge.pki.createCertificate();
  gRootCert.publicKey = gRootKeyPair.publicKey;
  gRootCert.serialNumber = "01";
  gRootCert.validity.notBefore = new Date();
  gRootCert.validity.notAfter = new Date();
  gRootCert.validity.notAfter.setFullYear(gRootCert.validity.notBefore.getFullYear() + 1);
  gRootCert.setSubject(name);
  gRootCert.setIssuer(name);
  gRootCert.setExtensions([{
    name: "basicConstraints",
    cA: true
  }, {
    name: "keyUsage",
    keyCertSign: true,
  }, {
    name: "extKeyUsage",
    serverAuth: true,
  }, {
    name: "subjectKeyIdentifier"
  }]);
  
  try {
    updateStatus(tag, "(signing certificate)", CLASS_PROGRESS);
    gRootCert.sign(gRootKeyPair.privateKey);
  } catch (err) {
    updateStatus(tag, "(error signing certificate)", CLASS_ERROR);
    console.log(err);
    return;
  }

  /* Prepare the key and certificate for download */
  gRootKeyPEM = forge.pki.privateKeyToPem(gRootKeyPair.privateKey);
  gRootCertPEM = forge.pki.certificateToPem(gRootCert);
  updateStatus(tag, "(done)", CLASS_DONE);
  return;
}

function downloadRootKey()  { saveFile(FILE_ROOT_KEY, gRootKeyPEM); }
function downloadRootCert() { saveFile(FILE_ROOT_CERT, gRootCertPEM); }


/*** Server certificate generation ***/

// TODO


/*** Ready handler ***/

$(document).ready(function() {
  $("#makeRoot").click(makeRoot);
  $("#downloadRootKey").click(downloadRootKey);
  $("#downloadRootCert").click(downloadRootCert);
});
