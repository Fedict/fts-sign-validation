package com.bosa.signandvalidation.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data @NoArgsConstructor @AllArgsConstructor
public class TrustSources {

    @Schema(description = "The password of the keystore")
    private String password;
    @Schema(description = "A PKCS12 Key store file (.p12)")
    private byte[] keystore;
    @Schema(description = "A list of certificates files (.cer)")
    private List<byte []> certs;
}
