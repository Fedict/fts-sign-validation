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
    private boolean xadesMultifile;
    private String bucket;
    private Integer signTimeout;
    private List<String> nnAllowedToSign;
    private boolean requestDocumentReadConfirm; // Request the user to check a "I have read the file" box before signing
    private boolean previewDocuments; // If true, display documents in the sign screen, otherwise provide list of downloadable links

    private String signProfile;
    private PolicyParameters policy;

    private String path; // Path of all the files in the bucket to Sign
    private List<TokenSignInput> inputs;

    private String outXsltPath;
    private String outFilePath;
    private boolean outDownload;

    // Mandatory parameters
    public TokenObject(boolean xadesMultifile, String bucket, String signProfile, List<TokenSignInput> inputs, String outFilePath) {
        this.xadesMultifile = xadesMultifile;
        this.inputs = inputs;
        this.bucket = bucket;
        this.signProfile = signProfile;
        this.outFilePath = outFilePath;
    }
}