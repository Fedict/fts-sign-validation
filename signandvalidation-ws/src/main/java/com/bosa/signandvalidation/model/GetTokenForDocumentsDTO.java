/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 *
 * @author cmo
 */
@Setter
@Getter
@NoArgsConstructor
public class GetTokenForDocumentsDTO {
    private SigningType signType;
    private String bucket;
    private String password;
    private Integer signTimeout;
    private boolean requestDocumentReadConfirm; // Request the user to check a "I have read the file" box before signing
    private boolean previewDocuments; // If true, display documents in the sign screen, otherwise provide list of downloadable links
    private List<String> nnAllowedToSign;

    private String signProfile;
    private PolicyDTO policy;

    private List<SignInput> inputs;

    private String outXsltPath;
    private String outFilePath;
    private String outPathPrefix;
    private boolean outDownload;

    // Mandatory parameters
    public GetTokenForDocumentsDTO(String bucket, String password, String signProfile, List<SignInput> inputs, String outFilePath) {
        this.inputs = inputs;
        this.bucket = bucket;
        this.password = password;
        this.signProfile = signProfile;
        this.outFilePath = outFilePath;
    }
}