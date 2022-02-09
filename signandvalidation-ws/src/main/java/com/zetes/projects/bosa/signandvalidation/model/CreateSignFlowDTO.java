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


/*
        “out”: “Result file with new signature”,

                "name": "abucket",
                "pwd": "string",
                "prof": "XADES_LTA",
                "signTimeout": 0,
                "allowedToSign": [
                {
                "nn": "35434534534345"
                }]
                "policyDescription": "Policiy….",
                "policyDigestAlgorithm": "SHA256",
                "policyId": " http://.............................",
                "xslt": " BoSa 2 just.xslt"

                "inputs" : [
                {
                "in": "[Bucket Path]a.XML",
                "noDownload": true,
                "requestDocumentReadConfirm": true,
                "xslt": "PimpMe.xslt",
                “id”: “D0”
                },
                {
                "in": "[Bucket Path]a.PDF",
                "noDownload": true,
                "requestDocumentReadConfirm": true,
                “Id”: “D1”
                }
                ]
                }
                */