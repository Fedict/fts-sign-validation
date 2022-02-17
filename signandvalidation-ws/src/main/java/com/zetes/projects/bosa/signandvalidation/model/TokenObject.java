/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

import com.zetes.projects.bosa.signingconfigurator.model.PolicyParameters;
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

    private String signProfile;
    private PolicyParameters policy;

    private List<SignInput> inputs;

    private String outXslt;
    private String outFileName;
    private boolean outDownload;

    // Mandatory parameters
    public TokenObject(boolean xadesMultifile, String bucket, String signProfile, List<SignInput> inputs, String outFileName) {
        this.xadesMultifile = xadesMultifile;
        this.inputs = inputs;
        this.bucket = bucket;
        this.signProfile = signProfile;
        this.outFileName = outFileName;
    }
}