package com.bosa.signandvalidation.model.rsign;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class DocumentDigest {
    private String label;
    private byte[] hash;
}
