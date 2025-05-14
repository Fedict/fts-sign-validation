
package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class FileToConsent {
    private String label;
    private byte[] hash;
    private Integer index;
}
