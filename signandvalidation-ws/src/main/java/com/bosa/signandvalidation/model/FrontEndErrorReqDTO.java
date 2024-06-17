package com.bosa.signandvalidation.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class FrontEndErrorReqDTO {

    private String err;
    private String report;
    private String result;
    private String token;
}
