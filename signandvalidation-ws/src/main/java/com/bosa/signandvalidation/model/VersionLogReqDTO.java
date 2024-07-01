/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.bosa.signandvalidation.exceptions.Utils;
import lombok.Data;

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
}
