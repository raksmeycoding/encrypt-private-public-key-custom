package com.raksmey.hybridEncryption.hybridEncAndIv;

import com.raksmey.hybridEncryption.utils.RsaKeyGenerator;
import lombok.SneakyThrows;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class HybridEncryptWithIV {

    // Encrypt AES key using RSA
    public static byte[] encryptAESKeyWithRSA(PublicKey publicKey, SecretKey aesKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsaCipher.doFinal(aesKey.getEncoded());
    }

    // Encrypt AES key using RSA
    public static byte[] encryptAESKeyWithRSA(PublicKey publicKey, byte[] aesKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsaCipher.doFinal(aesKey);
    }

    // Decrypt AES key using RSA
    public static SecretKey decryptAESKeyWithRSA(PrivateKey privateKey, byte[] encryptedAESKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAESKey);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    @SneakyThrows
    public static byte[] encryptIvWithRSA(PublicKey publicKey, byte[] iv) {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(iv);
    }

    ;

    @SneakyThrows
    public static byte[] decryptIvWithRSA(PrivateKey privateKey, byte[] iv) {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(iv);
    }


    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, new SecureRandom());
        return keyGenerator.generateKey();
    }

    public static byte[] generateAESKeyAsByteArray() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, new SecureRandom());
        return keyGenerator.generateKey().getEncoded();
    }


    public static byte[] generateIV() {
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static String generateIVasBase64() {
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    // Encrypt data user AES with IV
    public static byte[] encryptDataWithAESAndIv(SecretKey secretKey, byte[] data, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return aesCipher.doFinal(data);
    }


    // Decrypt data using AES with IV
    public static byte[] decryptDataWithAESAndIv(SecretKey aesKey, byte[] encryptedData, byte[] iv) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        return aesCipher.doFinal(encryptedData);
    }

    // Decrypt data using AES with IV
    public static String decryptDataWithAESAndIv(SecretKey aesKey, String encryptedData, byte[] iv) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        return Base64.getEncoder().encodeToString(aesCipher.doFinal(Base64.getDecoder().decode(encryptedData)));
    }


    public static String base64Encoded(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    public static byte[] base64Decode(String s) {
        return Base64.getDecoder().decode(s);
    }


    @SneakyThrows
    public static void main(String[] args) {
        KeyPair keyPair = RsaKeyGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Gen Secret Key (ASE Key)
        SecretKey secretKey = generateAESKey();
        String originalSecreteAsString = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        byte[] encryptASEKeyWithRSA = encryptAESKeyWithRSA(publicKey, secretKey);
        String encryptASEKeyWithRSAToString = base64Encoded(encryptASEKeyWithRSA);
        SecretKey decryptedSecreteKey = decryptAESKeyWithRSA(privateKey, encryptASEKeyWithRSA);
        byte[] decodeSecreteKey = decryptedSecreteKey.getEncoded();
        String decodeSecreteKeyAsString = Base64.getEncoder().encodeToString(decodeSecreteKey);

        System.out.printf("""
                        Original secrete key as byte: %s
                        Original secrete key as string encoded: %s
                        Encrypt ASE Key to Byte: %s
                        Encrypt ASE Key to String: %s
                                                
                        Decrypt ASE original as byte array: %s
                        Decrypt ASE as original string: %s
                        """,
                Arrays.toString(secretKey.getEncoded()),
                originalSecreteAsString,
                Arrays.toString(encryptASEKeyWithRSA),
                encryptASEKeyWithRSAToString,
                Arrays.toString(decodeSecreteKey),
                decodeSecreteKeyAsString
        );


        // Gen Iv for encrypt data with ASE Key
        byte[] secureIv = generateIV();
//        String encryptSecrueIv = en
//
//        System.out.printf("""
//                Iv as byte: %s
//                """, Arrays.toString(secureIv));


    }
}
