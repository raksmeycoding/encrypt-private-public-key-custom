package com.raksmey.hybridEncryption.controller;

import com.raksmey.hybridEncryption.model.EncryptedBody;
import com.raksmey.hybridEncryption.service.TestDecryptService;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
@RequiredArgsConstructor
public class TestDecryptController {

    private final TestDecryptService testDecryptService;

    @PostMapping("/decrypt")
    @SneakyThrows
    public ResponseEntity<String> testDecryptData(@RequestBody EncryptedBody data) {
        try {
            String decryptedData = testDecryptService.decryptToRawData(data);
            return ResponseEntity.ok(decryptedData);
        } catch (Exception e) {
            // Log the exception details for debugging
            System.err.println("Error during decryption: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(500).body("Internal Server Error: " + e.getMessage());
        }
    }

    // Exception handler for better logging
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e) {
        System.err.println("Unhandled exception: " + e.getMessage());
        e.printStackTrace();
        return ResponseEntity.status(500).body("Internal Server Error: " + e.getMessage());
    }
}
