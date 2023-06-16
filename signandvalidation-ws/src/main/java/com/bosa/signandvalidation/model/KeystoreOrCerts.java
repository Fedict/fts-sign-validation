package com.bosa.signandvalidation.model;

import lombok.Data;

import java.util.List;

@Data
public class KeystoreOrCerts {
    private String password;
    private byte[] keystore;
    private List<byte []> certs;
}
