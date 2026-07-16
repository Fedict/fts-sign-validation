/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.bosa.signandvalidation.exceptions.Utils;
import lombok.Data;
import org.slf4j.MDC;

/**
 *
 * @author christian
 */
@Data
public class VersionLogReqDTO {
    private String frontEndType;
    private String frontEnd;
    private String beID;
    private String browserExt;
    private String browserStore;
    private String token;
    private String userAgent;

    public void sanitize() {
        frontEndType        = Utils.sanitize(frontEndType, 20);
        frontEnd            = Utils.sanitize(frontEnd, 20);
        beID                = Utils.sanitize(beID, 20);
        browserExt          = Utils.sanitize(browserExt, 20);
        browserStore        = Utils.sanitize(browserStore, 20);
        userAgent           = Utils.sanitize(userAgent, 256);
    }

    public void toMDC() {
        MDC.put("frontEndType", frontEndType);
        MDC.put("frontEnd", frontEnd);
        MDC.put("beID", beID);
        MDC.put("browserExt", browserExt);
        MDC.put("browserStore", browserStore);
        MDC.put("token", token);
        MDC.put("userAgent", userAgent);
    }
}
