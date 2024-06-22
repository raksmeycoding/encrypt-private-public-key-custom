package com.raksmey.hybridEncryption.utils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyLoader {

    public static PublicKey loadPublicKey(String filePath) throws Exception {
        String keyString = new String(Files.readAllBytes(Paths.get(filePath)));
        String publicKeyPEM = keyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", ""); // Remove all whitespace
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        String keyString = new String(Files.readAllBytes(Paths.get(filePath)));
        String privateKeyPEM = keyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", ""); // Remove all whitespace

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static void main(String[] args) {
        String publicKeyPath = "src/main/resources/keys/publicKey.pem";
        String privateKeyPath = "src/main/resources/keys/privateKey.pem";

        try {
            // Load public key from file
            PublicKey publicKey = loadPublicKey(publicKeyPath);
            System.out.println("Loaded Public Key: " + publicKey);

            // Load private key from file
            PrivateKey privateKey = loadPrivateKey(privateKeyPath);
            System.out.println("Loaded Private Key: " + privateKey);
        } catch (Exception e) {
            System.err.println("Error loading keys: " + e.getMessage());
        }
    }
}
