package com.raksmey.hybridEncryption.rsaencrypt;

import com.raksmey.hybridEncryption.utils.KeyLoader;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

public class RSAEncryption {

    public static String encrypt (String plainText, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptBytes);
    }

    public static String decrypt(String encryptedText, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }


    public static void main(String[] args) throws Exception {
        PublicKey publicKey = KeyLoader.loadPublicKey("src/main/resources/keys/publicKey.pem");
        PrivateKey privateKey = KeyLoader.loadPrivateKey("src/main/resources/keys/privateKey.pem");


        // Test Encrypt
        String data = "Hello How are you doing brother?";
        String cipherText = encrypt(data, publicKey);
        System.out.println("Encrypt data: " + cipherText);



        for (int i = 0; i < 3; i++) {
            String decryptData = decrypt(cipherText, privateKey);
            System.out.println("Decrypt result: " + i + " " + decryptData);
        }
    }
}
