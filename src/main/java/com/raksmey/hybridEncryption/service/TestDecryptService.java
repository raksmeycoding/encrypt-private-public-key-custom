package com.raksmey.hybridEncryption.service;

import com.raksmey.hybridEncryption.model.EncryptedBody;

public interface TestDecryptService {

     String decryptToRawData(EncryptedBody encryptedBody);

}
