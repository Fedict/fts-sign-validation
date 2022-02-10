/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

import com.zetes.projects.bosa.signingconfigurator.model.PolicyParameters;
import lombok.Data;
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
public class CreateSignFlowDTO {
    private String bucket;
    private String password;
    private Integer signTimeout;
    private List<String> nnAllowedToSign;

    private String signProfile;
    private PolicyParameters policy;

    private List<XmlSignInput> inputs;

    private String outXslt;
    private String outFileName;

    public CreateSignFlowDTO(String bucket, String password, String signProfile, List<XmlSignInput> inputs, String outFileName) {
        this.inputs = inputs;
        this.bucket = bucket;
        this.password = password;
        this.signProfile = signProfile;
        this.outFileName = outFileName;
    }
}