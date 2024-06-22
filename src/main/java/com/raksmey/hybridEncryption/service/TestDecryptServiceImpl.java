package com.raksmey.hybridEncryption.service;


import com.raksmey.hybridEncryption.hybridEncAndIv.HybridEncryptWithIV;
import com.raksmey.hybridEncryption.model.EncryptedBody;
import com.raksmey.hybridEncryption.utils.KeyLoader;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.Base64;

@Service
public class TestDecryptServiceImpl implements TestDecryptService {

    @SneakyThrows
    public String decryptToRawData(@RequestBody EncryptedBody encryptedBody) {
        PrivateKey privateKey = KeyLoader.loadPrivateKey("src/main/resources/keys/privateKey.pem");
        SecretKey secretKey = HybridEncryptWithIV.decryptAESKeyWithRSA(privateKey, HybridEncryptWithIV.base64Decode(encryptedBody.getKey()));
        byte[] iv = HybridEncryptWithIV.decryptIvWithRSA(privateKey, Base64.getDecoder().decode(encryptedBody.getIv()));


        byte[] encryptData = Base64.getDecoder().decode(encryptedBody.getData());


        return HybridEncryptWithIV.decryptDataWithAESAndIv(secretKey, encryptedBody.getData(), iv);
    }
}
