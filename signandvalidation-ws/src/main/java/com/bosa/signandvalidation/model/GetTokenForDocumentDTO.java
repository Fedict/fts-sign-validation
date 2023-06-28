/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import io.swagger.v3.oas.annotations.media.Schema;
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

    @Schema(name = "name", example = "0qtp70go8n3gcxosz88z", requiredMode = Schema.RequiredMode.REQUIRED, description = "The name of the bucket where the files (pdf/xml/xlst/psp) are stored, also the username to authenticate on the S3 server")
    private String name;
    @Schema(name = "pwd", example = "S3cr3t!PAsSv0rd", requiredMode = Schema.RequiredMode.REQUIRED, description = "The password to authenticate on the S3 server")
    private String pwd;
    @Schema(name = "in", example = "ToBeSigned.xml", requiredMode = Schema.RequiredMode.REQUIRED, description = "The name of the file, stored on the S3 server, that must be signed")
    private String in;
    @Schema(name = "out", example = "Signed.xml", requiredMode = Schema.RequiredMode.REQUIRED, description = "The name of the signed file that will be created on the S3 server")
    private String out;
    @Schema(name = "prof", example = "XADES_LTA", requiredMode = Schema.RequiredMode.REQUIRED, description = "The signing profile to use")
    private String prof;
    @Schema(name = "xslt", example = "RENDER.xslt", description = "The name of the file, stored on the S3 server, that must be used to improve the display of the XML to be signed. Only applicable to XML files")
    private String xslt;
    @Schema(name = "psp", example = "MainSignatureType.psp", description = "The name of the file, stored on the S3 server, that describes how the visible signature of a PDF to sign must rendered. Example of a PSP file:  { \n" +
            "\"name\":\"minfin\",\"pwd\":\"U84SnLEQvp\", \"in\":\"test.pdf\", \"out\":\"signed_test.pdf\", \"psp\":\"minfin1.psp\", \"psfC\":\"1,20,30,180,60\", \n" +
            "  \"psfP\":true, \"lang\":\"en\" } ")
    private String psp;   // PDF signature parameters file name
    @Schema(name = "psfN", example = "SignatureFieldManager", description = "The name of an Acroform contained in the PDF to sign where the signature must be rendered.")
    private String psfN;  // PDF signature field name
    @Schema(name = "psfC", example = "1,200,200,300,100", description = "The position where the visible signature signature in a PDF to sign will be placed. Format : <Page Number>,<X>,<Y>,<Width>,<Height>.")
    private String psfC;  // PDF signature field coordinates
    @Schema(name = "psfP", example = "true", description = "A boolean, if true it means the visible signature of a PDF to sign will include hte picture of the EID")
    private String psfP;  // Include eID photo as icon in the PDF signature field
    @Schema(name = "lang", example = "en", description = "The language in which the visible signature text of a PDF will be rendered")
    private String lang;
    @Schema(name = "signTimeout", example = "150", description = "If the time between a user clicks on the “I want to Sign” button and the moment he signs the document is greater than the number of seconds defined by “signTimeout” the signature will be rejected.")
    private Integer signTimeout;        // if Null -> default Timeout (120s) , otherwise # seconds between the getDataToSignForToken and the time when sign will be rejected
    @Schema(name = "noDownload", example = "true", description = "If “true”, the user will not be allowed to download the signed file")
    private boolean noDownload;
    private List<AllowedToSign> allowedToSign;
    @Schema(name = "policyId", example = "http://policy.hom.com/policy", description = "Only for XML documents. If present it will be added to the signature.")
    private String policyId;
    @Schema(name = "policyDescription", example = "Belgium signing Policy", description = "Only for XML documents. If present it will be added to the signature.")
    private String policyDescription;
    @Schema(name = "policyDigestAlgorithm", example = "SHA512", description = "The digest algorithm used to make the policy digest. Only for XML documents. If present it will be added to the signature.")
    private String policyDigestAlgorithm;
    @Schema(name = "requestDocumentReadConfirm", example = "true", description = "If “true”, display a “I have read this document.*” checkbox to the sign user interface that must be checked before signing is allowed")
    private boolean requestDocumentReadConfirm;
}
