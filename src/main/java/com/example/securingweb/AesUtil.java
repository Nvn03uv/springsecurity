package com.example.securingweb;
import java.io.UnsupportedEncodingException;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class AesUtil {
    private final int keySize;
    private final int iterationCount;
    private final Cipher cipher;
    
    public AesUtil(int keySize, int iterationCount) {
        this.keySize = keySize;
        this.iterationCount = iterationCount;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw fail(e);
        }
    }
    
    public String encrypt(String salt, String iv, String passphrase, String plaintext) {
        try {
            SecretKey key = generateKey(salt, passphrase);
            byte[] encrypted = doFinal(Cipher.ENCRYPT_MODE, key, iv, plaintext.getBytes("UTF-8"));
            return base64(encrypted);
        }
        catch (UnsupportedEncodingException e) {
            throw fail(e);
        }
    }
    
    public String decrypt(String salt, String iv, String passphrase, String ciphertext) {
        try {
            SecretKey key = generateKey(salt, passphrase);
            byte[] decrypted = doFinal(Cipher.DECRYPT_MODE, key, iv, base64(ciphertext));
            return new String(decrypted, "UTF-8");
        }
        catch (UnsupportedEncodingException e) {
            throw fail(e);
        }
    }
    
    public static  String getDcrypt(String encryptedPass, String username) {
    	
    	
    	
    	String salt =  encryptedPass.substring(0,32); // "29dd525a97821c1b33b79f6aec9a5672";
    	System.out.println(salt);
    	String iv = encryptedPass.substring(32,64); // "a1f9670b0959c323e35d6f96acb225f0";
    	System.out.println(iv);
    	String ciphertext = encryptedPass.substring(64); //JFjqMSCw+D4I0mqs07OkLg==
    	System.out.println(ciphertext);
    	
    	//login.component.ts:99 transitmessage : 29dd525a97821c1b33b79f6aec9a5672a1f9670b0959c323e35d6f96acb225f0JFjqMSCw+D4I0mqs07OkLg==
    	AesUtil aes = new AesUtil(256, 1000);
    	return aes.decrypt(salt, iv, username, ciphertext);
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
            SecretKeyFactory factory = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), hex(salt), iterationCount, keySize);
            SecretKey key = new SecretKeySpec(factory.
                    generateSecret(spec).getEncoded(), "AES");
            return key;
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw fail(e);
        }
    }
    
    public static String random(int length) {
        byte[] salt = new byte[length];
        new SecureRandom().nextBytes(salt);
        return hex(salt);
    }
    
    public static String base64(byte[] bytes) {
        return new String(Base64.encodeBase64(bytes));
    }
    
    public static byte[] base64(String str) {
        return Base64.decodeBase64(str.getBytes());
    }
    
    public static String hex(byte[] bytes) {
        return new String(Hex.encodeHex(bytes));
    }
    
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
}