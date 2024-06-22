package com.raksmey.hybridEncryption;

import com.raksmey.hybridEncryption.utils.RsaKeyGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class HybridEncryptionApplicationTests {


	@Test
	void testGenerateKeyPair() throws NoSuchAlgorithmException {
		KeyPair keyPair = RsaKeyGenerator.generateKeyPair();

		assertNotNull(keyPair, "KeyPair should not be null");

		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		assertNotNull(publicKey, "Public key should not be null");
		assertNotNull(privateKey, "Private key should not be null");

		assertEquals("RSA", publicKey.getAlgorithm(), "Algorithm of public key should be RSA");
		assertEquals("RSA", privateKey.getAlgorithm(), "Algorithm of private key should be RSA");

		assertTrue(publicKey.getEncoded().length > 0, "Public key should have a non-zero length");
		assertTrue(privateKey.getEncoded().length > 0, "Private key should have a non-zero length");
	}
}
