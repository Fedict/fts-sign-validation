package com.bosa.signandvalidation.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.List;

@Data
public class TrustSources {

    @Schema(description = "The password of the keystore")
    private String password;
    @Schema(description = "A PKCS12 Key store file (.p12)")
    private byte[] keystore;
    @Schema(description = "A list of certificates files (.cer)")
    private List<byte []> certs;
}
