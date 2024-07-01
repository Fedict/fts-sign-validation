package com.bosa.signandvalidation.model;

import com.bosa.signandvalidation.exceptions.Utils;
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

    public void sanitize() {
        err                 = Utils.sanitize(err, 256);
        report              = Utils.sanitize(report, 120);
        result              = Utils.sanitize(result, 120);
    }
}
