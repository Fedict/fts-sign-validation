/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 *
 * @author wouter
 */
@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class GetTokenForDocumentDTO {
    private String name;
    private String pwd;
    private String in;
    private String out;
    private String prof;
    private String xslt;
    private String psp;   // PDF signature parameters file name
    private String psfN;  // PDF signature field name
    private String psfC;  // PDF signature field coordinates
    private String psfP;  // Include eID photo as icon in the PDF signature field
    private String lang;
    private Integer signTimeout;        // if Null -> default Timeout (120s) , otherwise # seconds between the getDataToSignForToken and the time when sign will be rejected
    private boolean noDownload;
    private List<AllowedToSign> allowedToSign;
    private String policyId;
    private String policyDescription;
    private String policyDigestAlgorithm;
    private boolean requestDocumentReadConfirm;

    public String toString() {
        String theString = null;
        try {
            theString = new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            theString = e.toString();
        }
        return theString;
    }
}
