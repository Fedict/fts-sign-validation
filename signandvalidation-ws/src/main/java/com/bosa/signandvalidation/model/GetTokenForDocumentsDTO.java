/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.bosa.signandvalidation.exceptions.Utils;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.slf4j.MDC;

import java.util.List;

/**
 *
 * @author cmo
 */
@Setter
@Getter
@NoArgsConstructor
public class GetTokenForDocumentsDTO {
    @Schema(example = "0qtp70go8n3gcxosz88z", requiredMode = Schema.RequiredMode.REQUIRED, description = "The name of the bucket where the files (pdf/xml/xlst/psp) are stored, also the username to authenticate on the S3 server")
    private String bucket;
    @Schema(example = "S3cr3t!PAsSv0rd", description = "The password to authenticate on the bucket for user/password authentication")
    private String password;
    @Schema(example = "eyJhbGciOiJSUzI1NiIsIn.UzI1NiIsInR5.cCIgOiAiSldUIiwia2lk", description = "Tha access token obtained form the oauth server")
    private String accessToken;
    @Schema(example = "300", description = "The time, in seconds before the access token expires")
    private Integer expiration;

    @Schema(example = "150", description = "If the time between a user clicks on the 'I want to Sign' button and the moment he signs the document is" +
            " greater than the number of seconds defined by “signTimeout” the signature will be rejected.<BR>Default value : 120 Seconds.")
    private Integer signTimeout;
    @Schema(example = "true", description = "If “true”, display a 'I have read this document' checkbox to the sign user interface that must be checked before signing is allowed")
    private boolean requestDocumentReadConfirm;
    @Schema(example = "true", description = "If true, display documents in the sign screen, otherwise provide list of downloadable links")
    private boolean previewDocuments;
    @Schema(example = "true", description = "If true, allow the user to select individual documents. Not valid for XadesMultiFile signType")
    private boolean selectDocuments;
    @Schema(example = "true", description = "If true, do not allow the user to skip signing a file in case of error")
    private boolean noSkipErrors;
    @Schema(example = "[ 55050533154,44040422423 ]", description = "A list of belgian national numbers that are allowed to sign the document")
    private List<String> nnAllowedToSign;

    @Schema(example = "XADES_LTA", requiredMode = Schema.RequiredMode.REQUIRED, description = "The signing profile to use if there is only one type of file to sign (XML or PDF)")
    private String signProfile;
    @Schema(example = "PADES_LT", description = "In case the input contains both XML and PDF this is the second profile to use")
    private String altSignProfile;

    @Schema(description = "The list of input file definitions")
    private List<SignInput> inputs;

    @Schema(example = "extra/justReport.xslt", description = "Only for XadesMultifile signature. The path of XSLT used to format the signed output file.<BR>" +
            "If not defined the standard output XML will be used.<BR>Sample standard format:<PRE><CODE>" +
            "<root>" +
            "   <file id=”ID1” name=”File1” size=”123”>BASE64_File_content</file><BR>" +
            "   <file id=”ID2” name=”File2” size=”456”>BASE64_File_content</file><BR>" +
            "</root></CODE></PRE>")
    private String outXsltPath;
    @Schema(example = "signed/out.xml", description = "The path of the signed file that will be created on the bucket. mutually exclusive with 'outPathPrefix'")
    private String outFilePath;
    @Schema(example = "out/signed_", description = "If set, the signed files will be stored on the bucket with their filename prefixed wih this path. mutually exclusive with 'outXsltPath'")
    private String outPathPrefix;
    @Schema(example = "true", description = "If “true”, the user will be allowed to download the signed file")
    private boolean outDownload;

    // Mandatory parameters
    public GetTokenForDocumentsDTO(String bucket, String password, String accessToken, Integer expiration, String signProfile, List<SignInput> inputs, String outFilePath) {
        this.inputs = inputs;
        this.bucket = bucket;
        this.password = password;
        this.expiration = expiration;
        this.accessToken = accessToken;
        this.signProfile = signProfile;
        this.outFilePath = outFilePath;
    }

    public void toMDC() {
        MDC.put("bucket", bucket);
        MDC.put("requestDocumentReadConfirm", String.valueOf(requestDocumentReadConfirm));
        MDC.put("previewDocuments", String.valueOf(previewDocuments));
        MDC.put("selectDocuments", String.valueOf(selectDocuments));
        MDC.put("noSkipErrors", String.valueOf(noSkipErrors));
        MDC.put("outDownload", String.valueOf(outDownload));
        if (signTimeout != null) MDC.put("signTimeout", String.valueOf(signTimeout));
        Utils.toMDCIfNotNull("outXsltPath", outXsltPath);
        Utils.toMDCIfNotNull("outFilePath", outFilePath);
        Utils.toMDCIfNotNull("outPathPrefix", outPathPrefix);
        Utils.toMDCIfNotNull("signProfile", signProfile);
        Utils.toMDCIfNotNull("altSignProfile", altSignProfile);
        if (nnAllowedToSign != null) {
            for (int i = 0; i < nnAllowedToSign.size(); i++) {
                Utils.toMDCIfNotNull("nnAllowedToSign" + "[" + i + "]", nnAllowedToSign.get(i));
            }
        }
        if (inputs != null) {
            for (int i = 0; i < inputs.size(); i++) {
                SignInput input = inputs.get(i);
                String key = "inputs" + "[" + i + "].";
                MDC.put(key + "psfP", String.valueOf(input.isPsfP()));
                MDC.put(key + "drawable", String.valueOf(input.getDrawable()));
                MDC.put(key + "signLanguage", String.valueOf(input.getSignLanguage()));
                Utils.toMDCIfNotNull(key + "psfC", input.getPsfC());
                Utils.toMDCIfNotNull(key + "psfN", input.getPsfN());
                Utils.toMDCIfNotNull(key + "fileURI", input.getFileURI());
                Utils.toMDCIfNotNull(key + "filePath", input.getFilePath());
                Utils.toMDCIfNotNull(key + "xmlEltId", input.getXmlEltId());
                Utils.toMDCIfNotNull(key + "pspFilePath", input.getPspFilePath());
                Utils.toMDCIfNotNull(key + "displayXsltPath", input.getDisplayXsltPath());
            }
        }
    }
}
