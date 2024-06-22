package com.raksmey.hybridEncryption.utils;


import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;

import javax.crypto.KeyGenerator;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;

public class RsaKeyGenerator {


    private static final Logger LOGGER = LoggerFactory.getLogger(RsaKeyGenerator.class);

    private static final String PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----\n";
    private static final String PRIVATE_KEY_FOOTER = "\n-----END PRIVATE KEY-----";
    private static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----\n";
    private static final String PUBLIC_KEY_FOOTER = "\n-----END PUBLIC KEY-----";

    public enum RSA_KEY {
        PUBLIC_BINARY,
        PRIVATE_BINARY,
        PUBLIC_STRING,
        PRIVATE_STRING,

    }

    private RsaKeyGenerator() {
    }

    public static RsaKeyGenerator getInstance() {
        return new RsaKeyGenerator();
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();

    }


    public void generateRsaKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
        String publicKeyName = "publicKey.pem";
        String privateKeyName = "privateKey.pem";
        saveToResourceAsString(keyPair.getPublic(), publicKeyName, PUBLIC_KEY_HEADER, PUBLIC_KEY_FOOTER);
        saveToResourceAsString(keyPair.getPrivate(), privateKeyName, PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER);
        LOGGER.info("Keys created...");
    }


    private static void saveToResourceAsBinary(Key key, String resourceName) {
        // Check directory of keys
        checkResourcesFilesPath();
        // Save file to the directory
        try (OutputStream fos = new FileOutputStream("src/main/resources/keys/" + resourceName)) {
            fos.write(key.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void saveToResourceAsString(Key key, String resourceName, String header, String footer) {
        // Check directory of keys
        checkResourcesFilesPath();
        // Save file to the directory
        try (OutputStream fos = new FileOutputStream("src/main/resources/keys/" + resourceName)) {
            String keyString = Base64.getEncoder().encodeToString(key.getEncoded());
            String pemKey = header + keyString + footer;
            fos.write(pemKey.getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void checkResourcesFilesPath() {
        // Directory name within the resource folder
        final String DIRECTORY = "keys";
        // Get the path to the resource folder
        Path resourcePath = Paths.get("src/main/resources");
        // Append the directory name to the resource folder
        Path directoryPath = resourcePath.resolve(DIRECTORY);
        // Check if the directory name to the resource path
        try {
            if (!Files.exists(directoryPath)) {
                Files.createDirectories(directoryPath);
                System.out.println("Directory created successfully.");
            } else {
                System.out.println("Directory is already exists.");
            }
        } catch (IOException e) {
            System.err.println("Failed to create directory: " + e.getMessage());
        }
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {
        RsaKeyGenerator rsaKeyGenerator = RsaKeyGenerator.getInstance();
        rsaKeyGenerator.generateRsaKey();
    }


}

