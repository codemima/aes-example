package org.cloudme.sample.aes;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 *
 */
public class AesUtil {
    /**
     * 参考: https://github.com/codemima/aes-example
     */

    private final int keySize;
    private final int iterationCount;
    private final Cipher cipher;
    // 此处将构造方法私有化,只允许调用静态方法。 可根据需要修改
    private AesUtil(int keySize, int iterationCount) {
        this.keySize = keySize;
        this.iterationCount = iterationCount;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw fail(e);
        }
    }
    // 内部方法; 加密(盐, 偏移量, 密码, 纯文本明文字符串)
    private String encrypt(String salt, String iv, String passphrase, String plaintext) {
        try {
            SecretKey key = generateKey(salt, passphrase);
            byte[] encrypted = doFinal(Cipher.ENCRYPT_MODE, key, iv, plaintext.getBytes("UTF-8"));
            return base64(encrypted);
        }
        catch (UnsupportedEncodingException e) {
            throw fail(e);
        }
    }
    // 内部方法; 解密(盐, 偏移量, 密码, 密文字符串)
    private String decrypt(String salt, String iv, String passphrase, String ciphertext) {
        try {
            SecretKey key = generateKey(salt, passphrase);
            byte[] decrypted = doFinal(Cipher.DECRYPT_MODE, key, iv, base64(ciphertext));
            return new String(decrypted, "UTF-8");
        }
        catch (UnsupportedEncodingException e) {
            throw fail(e);
        }
    }

    private byte[] doFinal(int encryptMode, SecretKey key, String iv, byte[] bytes) {
        try {
            cipher.init(encryptMode, key, new IvParameterSpec(hex(iv)));
            return cipher.doFinal(bytes);
        }
        catch (InvalidKeyException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException
                | BadPaddingException e) {
            throw fail(e);
        }
    }

    private SecretKey generateKey(String salt, String passphrase) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), hex(salt), iterationCount, keySize);
            SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            return key;
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw fail(e);
        }
    }
    //
    private static String random(int length) {
        byte[] salt = new byte[length];
        new SecureRandom().nextBytes(salt);
        return hex(salt);
    }
    // 二进制(byte[]) 转换为 base 64 字符串
    public static String base64(byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }
    //  base 64 字符串 转换为 二进制(byte[])
    public static byte[] base64(String str) {
        return Base64.decodeBase64(str);
    }
    // 二进制(byte[]) 转换为 16进制格式的 字符串
    public static String hex(byte[] bytes) {
        return Hex.encodeHexString(bytes);
    }
    //  16进制格式的 字符串 转换为 二进制(byte[])
    public static byte[] hex(String str) {
        try {
            return Hex.decodeHex(str.toCharArray());
        }
        catch (DecoderException e) {
            throw new IllegalStateException(e);
        }
    }

    private IllegalStateException fail(Exception e) {
        return new IllegalStateException(e);
    }
    // 加密字符串; 内含特定的盐和偏移量;加解密需要一致
    public static String encryptoString(String plainText, String key){
        String passphrase = key; // 密码
        int iterationCount = 10; // 迭代次数
        int keySize = 128; // key的长度
        String salt =getKeyByLength(key, 32); // 盐
        String iv = getKeyByLength(key, 32); // 初始化向量

        AesUtil aesUtil = new AesUtil(keySize, iterationCount);
        String plaintext = aesUtil.encrypt(salt, iv, passphrase, plainText);
        //
        return plaintext;
    }
    // 解密字符串; 内含特定的盐和偏移量;加解密需要一致
    public static String decryptoString(String ciphertext, String key){
        String passphrase = key; // 密码
        int iterationCount = 10; // 迭代次数
        int keySize = 128; // key的长度
        String salt =getKeyByLength(key, 32); // 盐
        String iv = getKeyByLength(key, 32); // 初始化向量

        AesUtil aesUtil = new AesUtil(keySize, iterationCount);
        String plaintext = aesUtil.decrypt(salt, iv, passphrase, ciphertext);
        //
        return plaintext;
    }
    // 此方法可根据需要修改
    private static String getKeyByLength(String key, int len){
        if(null == key || key.isEmpty()){
            key = "noKeys";
        }
        //
        while(key.length() < len){
            key = key + key;
        }
        if(key.length() > len){
            key = key.substring(0, len);
        }
        //
        return key;
    }
}

