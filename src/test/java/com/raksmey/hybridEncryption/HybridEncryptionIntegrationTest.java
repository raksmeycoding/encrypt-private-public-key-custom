package com.raksmey.hybridEncryption;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.raksmey.hybridEncryption.hybridEncAndIv.HybridEncryptWithIV;
import com.raksmey.hybridEncryption.model.EncryptedBody;
import com.raksmey.hybridEncryption.utils.KeyLoader;
import com.raksmey.hybridEncryption.utils.RsaKeyGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class HybridEncryptionIntegrationTest {

    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private ObjectMapper objectMapper;


    @Test
    void testSendEncryptData() throws Exception {
        // Generate RSA key pair
        PublicKey publicKey = KeyLoader.loadPublicKey("src/main/resources/keys/publicKey.pem");
        PrivateKey privateKey = KeyLoader.loadPrivateKey("src/main/resources/keys/privateKey.pem");

        // Generate ASE key
        SecretKey aseSecrete = HybridEncryptWithIV.generateAESKey();

        // Encrypt ASE key with public key
        byte[] encryptAseKey = HybridEncryptWithIV.encryptAESKeyWithRSA(publicKey, aseSecrete);

        // Convert ASE key and VI to Base64 encode
        String aseKeyBase64 = HybridEncryptWithIV.base64Encoded(encryptAseKey);
        byte[] ivBase64 = HybridEncryptWithIV.generateIV();
        byte[] encryptIv = HybridEncryptWithIV.encryptIvWithRSA(publicKey, ivBase64);

        // encrypt data;
        String rawData = "This is my raw data";
        byte[] encryptRawData = HybridEncryptWithIV.encryptDataWithAESAndIv(aseSecrete, rawData.getBytes(), ivBase64);
        String cypherText = Base64.getEncoder().encodeToString(encryptRawData);

        EncryptedBody encryptedBody = EncryptedBody.builder()
                .data(cypherText)
                .key(Base64.getEncoder().encodeToString(encryptAseKey))
                .iv(Base64.getEncoder().encodeToString(encryptIv))
                .build();


//        System.out.println("Decrypt Raw data: " + decryptData);
//        System.out.println("INput length: " + Arrays.toString(Base64.getDecoder().decode(ivBase64)));


        // Simulate frontend sending encrypt AES and IV to backend
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/json");

        String requestBody = objectMapper.writeValueAsString(encryptedBody);

        HttpEntity<String> request = new HttpEntity<>(requestBody, headers);
        // Full URL including protocol, hostname, and port
        String url = "http://localhost:" + 8080 + "/test/decrypt";
        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, request, String.class);

            System.out.println("Response: " + new String(Base64.getDecoder().decode(response.getBody())));

            // Verify backend response
            assertEquals(200, response.getStatusCode().value());

            // Decrypt response from backend
//            String decryptedResponse = HybridEncryptWithIV.decryptDataWithAES(privateKey, Base64.getDecoder().decode(response.getBody()), Base64.getDecoder().decode(ivBase64));
//            assertEquals("This is my secret message", decryptedResponse);
        } catch (HttpServerErrorException e) {
            // Log the server error response for debugging
            System.err.println("Server Error: " + e.getResponseBodyAsString());
            throw e;
        }
    }


}
