"use strict";

/*** Constants ***/

var KEY_SIZE = 2048;
var SERIAL_NUMBER_BYTES = 8;

var FILE_ROOT_KEY = "root.key.pem";
var FILE_ROOT_CERT = "root.cert.pem";
var FILE_SERVER_KEY = "server.key.pem";
var FILE_SERVER_CERT = "server.cert.pem";

// These should line up with CSS classes
var CLASS_PROGRESS = "statusProgress";
var CLASS_DONE = "statusDone";
var CLASS_ERROR = "statusError";


/*** State ***/

var gRootKeyPair;
var gRootCert;
var gRootKeyPEM;
var gRootCertPEM;

var gServerKeyPair;
var gServerCert;
var gServerKeyPEM;
var gServerCertPEM;


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

function fileLoader(callback) {
  return function(evt) {
    evt = evt.originalEvent || evt;
    window.myEvent = evt;
    var files = evt.target.files;
    for (var i=0; i < files.length; ++i) {
      (function(i) {
        var reader = new FileReader();
        reader.onload = function(e) {
          callback(e.target.result);
        }
        reader.readAsText(files[i]);
      })(i);
    }
  }
}


/*** Root generation ***/

function makeRoot() {
  var tag = "makeRoot";

  // Build the name from the entered name
  var enteredName = $("#rootName").val();
  if (!enteredName) {
    updateStatus(tag, "(enter a name)", CLASS_ERROR);
    return;
  }
  var name = [{
    name: "commonName",
    value: enteredName 
  }];

  // Generate a key pair
  updateStatus(tag, "(generating key)", CLASS_PROGRESS);
  gRootKeyPair = forge.pki.rsa.generateKeyPair(KEY_SIZE);

  // Create a self-signed certificate
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
    console.log("Error signing certificate" + err);
    return;
  }

  // Prepare the key and certificate for download
  gRootKeyPEM = forge.pki.privateKeyToPem(gRootKeyPair.privateKey);
  gRootCertPEM = forge.pki.certificateToPem(gRootCert);
  updateStatus(tag, "(done)", CLASS_DONE);
  return;
}

function downloadRootKey()  { saveFile(FILE_ROOT_KEY, gRootKeyPEM); }
function downloadRootCert() { saveFile(FILE_ROOT_CERT, gRootCertPEM); }


/*** Server certificate generation ***/

function loadRootKey(keyPEM) {
  var tag = "rootKey";

  try { 
    gRootKeyPair = {
      privateKey: forge.pki.privateKeyFromPem(keyPEM)
    };
  } catch (e) {
    console.log("Error parsing certificate: " + e);
    updateStatus(tag, "(error)", CLASS_ERROR);
    return;
  }

  updateStatus(tag, "(ok)", CLASS_DONE);
}

function loadRootCert(keyPEM) {
  var tag = "rootCert";

  try { 
    gRootCert = forge.pki.certificateFromPem(keyPEM);
  } catch (e) {
    console.log("Error parsing certificate: " + e);
    updateStatus(tag, "(error)", CLASS_ERROR);
    return;
  }

  updateStatus(tag, "(ok)", CLASS_DONE);
}

function checkServerNames() {
  var tag = "serverNames";
  const hostname = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/;

  // Should be whitespace-separated DNS names
  var serverNames = $("#serverNames").val().split(/\s+/);

  if (serverNames.length == 0) {
    console.log("Need a name");
    updateStatus(tag, "(need a name)", CLASS_PENDING);
    return false;
  }

  for (var i=0; i < serverNames.length; ++i) {
    if (!serverNames[i].match(hostname)) {
      console.log("Invalid name: " + serverNames[i]);
      updateStatus(tag, "(invalid)", CLASS_ERROR);
      return false;
    }
  }

  updateStatus(tag, "(ok)", CLASS_DONE);
  return serverNames;
}

function makeServer() {
  var tag = "makeServer";

  // Check that the root has been loaded 
  if (!gRootKeyPair || !gRootKeyPair.privateKey || !gRootCert) {
    updateStatus(tag, "(no root)", CLASS_ERROR);
    return;
  }

  // Check the server names
  var serverNames = checkServerNames();
  if (!serverNames) {
    updateStatus(tag, "(bad names)", CLASS_ERROR);
    return;
  }
  var subjectName = [{
    name: "commonName",
    value: serverNames[0]
  }];
  var altNames = serverNames.map(function(name) {
    return { type: 2, value: name };
  });

  // Generate a key pair
  updateStatus(tag, "(generating key)", CLASS_PROGRESS);
  gServerKeyPair = forge.pki.rsa.generateKeyPair(KEY_SIZE);

  // Generate a random serial number
  var serialNumber = forge.random.getBytesSync(SERIAL_NUMBER_BYTES);
  var serialNumberHex = "00" + forge.util.bytesToHex(serialNumber);

  // Create a certificate signed by the CA
  gServerCert = forge.pki.createCertificate();
  gServerCert.publicKey = gServerKeyPair.publicKey;
  gServerCert.serialNumber = serialNumberHex;
  gServerCert.validity.notBefore = new Date();
  gServerCert.validity.notAfter = new Date(gRootCert.validity.notAfter);
  gServerCert.setSubject(subjectName);
  gServerCert.setIssuer(gRootCert.issuer.attributes);
  gServerCert.setExtensions([{
    name: 'basicConstraints',
    cA: false
  }, {
    name: 'keyUsage',
    digitalSignature: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'extKeyUsage',
    serverAuth: true,
  }, {
    name: 'subjectAltName',
    altNames: altNames
  }, {
    name: 'subjectKeyIdentifier'
  }]);

  try {
    updateStatus(tag, "(signing certificate)", CLASS_PROGRESS);
    gServerCert.sign(gRootKeyPair.privateKey);
  } catch (err) {
    updateStatus(tag, "(error signing certificate)", CLASS_ERROR);
    console.log("Error signing certificate" + err);
    return;
  }

  // Prepare the key and certificate for download
  gServerKeyPEM = forge.pki.privateKeyToPem(gServerKeyPair.privateKey);
  gServerCertPEM = forge.pki.certificateToPem(gServerCert);
  updateStatus(tag, "(done)", CLASS_DONE);
  return;
}

function downloadServerKey()  { saveFile(FILE_SERVER_KEY, gServerKeyPEM); }
function downloadServerCert() { saveFile(FILE_SERVER_CERT, gServerCertPEM); }

/*** Ready handler ***/

$(document).ready(function() {
  $("#makeRoot").click(makeRoot);
  $("#downloadRootKey").click(downloadRootKey);
  $("#downloadRootCert").click(downloadRootCert);

  $("#rootKey").change(fileLoader(loadRootKey));
  $("#rootCert").change(fileLoader(loadRootCert));
  $("#serverNames").keyup(checkServerNames);
  $("#makeServer").click(makeServer);
  $("#downloadServerKey").click(downloadServerKey);
  $("#downloadServerCert").click(downloadServerCert);
});
