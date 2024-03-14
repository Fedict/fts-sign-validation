/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

import java.util.logging.Level;

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
}
