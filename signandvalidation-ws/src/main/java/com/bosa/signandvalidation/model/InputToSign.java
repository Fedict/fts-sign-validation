package com.bosa.signandvalidation.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class InputToSign {
    private Integer index;
    private String psfN;
    private String psfC;
    private boolean psfP;
    private String language;
}
