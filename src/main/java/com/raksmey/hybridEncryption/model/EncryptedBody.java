package com.raksmey.hybridEncryption.model;


import lombok.*;

@Setter
@Getter
@Builder
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class EncryptedBody {
    String key;
    String data;
    String iv;

}
