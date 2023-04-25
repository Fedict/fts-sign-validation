/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.PolicyParameters;
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
public class TokenObject {
    private long createTime;
    private SigningType signingType;
    private String bucket;
    private Integer signTimeout;
    private Integer tokenTimeout;
    private List<String> nnAllowedToSign;
    private boolean requestDocumentReadConfirm; // Request the user to check a "I have read the file" box before signing
    private boolean previewDocuments; // If true, display documents in the sign screen, otherwise provide list of downloadable links
    private boolean selectDocuments;
    private boolean skipErrors; // If true, allow the user to skip a file to sign

    private String pdfSignProfile;
    private String xmlSignProfile;
    private PolicyParameters policy;

    private String path; // Path of all the files in the bucket to Sign
    private List<TokenSignInput> inputs;

    private String outXsltPath;
    private String outFilePath;
    private String OutPathPrefix;
    private boolean outDownload;

    // Mandatory parameters
    public TokenObject(SigningType signingType, String bucket, String pdfSignProfile, String xmlSignProfile, List<TokenSignInput> inputs, String outFilePath) {
        this.signingType = signingType;
        this.inputs = inputs;
        this.bucket = bucket;
        this.outFilePath = outFilePath;
        this.pdfSignProfile = pdfSignProfile;
        this.xmlSignProfile = xmlSignProfile;
    }
}