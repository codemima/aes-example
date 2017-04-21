var AesUtil = function(keySize, iterationCount) {
  this.keySize = keySize / 32;
  this.iterationCount = iterationCount;
};

AesUtil.prototype.generateKey = function(salt, passPhrase) {
  var key = CryptoJS.PBKDF2(
      passPhrase, 
      CryptoJS.enc.Hex.parse(salt),
      { keySize: this.keySize, iterations: this.iterationCount });
  return key;
};

AesUtil.prototype.encrypt = function(salt, iv, passPhrase, plainText) {
  var key = this.generateKey(salt, passPhrase);
  var encrypted = CryptoJS.AES.encrypt(
      plainText,
      key,
      { iv: CryptoJS.enc.Hex.parse(iv) });
  return encrypted.ciphertext.toString(CryptoJS.enc.Base64);
};

AesUtil.prototype.decrypt = function(salt, iv, passPhrase, cipherText) {
  var key = this.generateKey(salt, passPhrase);
  var cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Base64.parse(cipherText)
  });
  var decrypted = CryptoJS.AES.decrypt(
      cipherParams,
      key,
      { iv: CryptoJS.enc.Hex.parse(iv) });
  return decrypted.toString(CryptoJS.enc.Utf8);
};

AesUtil.getKeyByLength=function (key, len){
    key = key || "noKeys";
    //
    len = len || 32;
    while(key.length < len){
        key = key + key;
    }
    if(key.length > len){
        key = key.substr(0, len);
    }
    return key;
};
//
AesUtil.encryptString=function (plainText, passphrase){
    if(!plainText || !passphrase){
        return "";
    }
    var iterationCount = 10; // 迭代次数
    var keySize = 128; // 密钥长度
    var iv = AesUtil.getKeyByLength(passphrase, 32); // 偏移量; initial-vector
    var salt = AesUtil.getKeyByLength(passphrase, 32);// 盐

    var aesUtil = new AesUtil(keySize, iterationCount);
    var ciphertext = aesUtil.encrypt(salt, iv, passphrase, plainText);
    // 返回密文
    return ciphertext;
};
AesUtil.decryptString=function (cipherText, passphrase){
    if(!cipherText || !passphrase){
        return "";
    }
    var iterationCount = 10; // 迭代次数
    var keySize = 128; // 密钥长度
    var iv = AesUtil.getKeyByLength(passphrase, 32); // 偏移量; initial-vector
    var salt = AesUtil.getKeyByLength(passphrase, 32);// 盐

    var aesUtil = new AesUtil(keySize, iterationCount);
    var mingwen = aesUtil.decrypt(salt, iv, passphrase, cipherText);
    // 返回明文
    return mingwen;
};
