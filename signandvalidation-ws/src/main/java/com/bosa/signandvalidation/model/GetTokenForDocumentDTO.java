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

    @Schema(example = "0qtp70go8n3gcxosz88z", requiredMode = Schema.RequiredMode.REQUIRED, description = "The name of the bucket where the files (pdf/xml/xlst/psp) are stored, also the username to authenticate on the S3 server")
    private String name;
    @Schema(example = "S3cr3t!PAsSv0rd", requiredMode = Schema.RequiredMode.REQUIRED, description = "The password to authenticate on the S3 server")
    private String pwd;
    @Schema(example = "ToBeSigned.xml", requiredMode = Schema.RequiredMode.REQUIRED, description = "The name of the file, stored on the S3 server, that must be signed")
    private String in;
    @Schema(example = "Signed.xml", requiredMode = Schema.RequiredMode.REQUIRED, description = "The name of the signed file that will be created on the S3 server")
    private String out;
    @Schema(example = "XADES_LTA", requiredMode = Schema.RequiredMode.REQUIRED, description = "The signing profile to use")
    private String prof;
    @Schema(example = "RENDER.xslt", description = "The name of the file, stored on the S3 server, that must be used to improve the display of the XML to be signed. Only applicable to XML files")
    private String xslt;
    @Schema(example = "MainSignatureType.psp", description = "The name of the file, stored on the S3 server, that describes how the visible signature of a PDF to sign must rendered. Example of a PSP file:<BR>" +
            "<PRE><CODE>{<BR>" +
            "  \"version\" : 2,<BR>" +
            "  \"bgColor\" : \"#D0D0D0\",<BR>" +
            "  \"texts\" : {<BR>" +
            "    \"en\" : \"Signed by %gn% %sn%\",<BR>" +
            "    \"de\" : \"Unterzeichnet von %gn% %sn%\",<BR>" +
            "    \"nl\" : \"Getekend door %gn% %sn%\",<BR>" +
            "    \"fr\" : \"Signé par %gn% %sn%\"<BR>" +
            "  },<BR>" +
            "  \"font\": \"freescpt\",<BR>" +
            "  \"textSize\" : 14,<BR>" +
            "  \"textPadding\" : 20,<BR>" +
            "  \"textAlignH\" : \"CENTER\",<BR>" +
            "  \"textAlignV\" : \"MIDDLE\",<BR>" +
            "  \"textPos\" : \"BOTTOM\",<BR>" +
            "  \"textColor\" : \"#0000FF\",<BR>" +
            "  \"defaultCoordinates\" : \"1,30,20,120,60\",<BR>" +
            "  \"imageDpi\" : 400,<BR>" +
            "  \"image\" : \"ZGVmYXVsdA==\" <BR>" +
            "} " +
            "</PRE></CODE>")
    private String psp;
    @Schema(example = "FleetManagerSignature", description = "The name of an existing Acroform of the PDF to sign where the signature must be rendered.")
    private String psfN;
    @Schema(example = "1,200,200,300,100", description = "The position where the visible signature signature in a PDF to sign will be placed. Format : 'Page Number,X,Y,Width,Height'. Example : '1,20,20,200,100'")
    private String psfC;
    @Schema(example = "true", description = "A boolean, if true it means the visible signature of a PDF to sign will include hte picture of the EID")
    private String psfP;
    @Schema(example = "en", description = "The language in which the visible signature text of a PDF will be rendered")
    private String lang;
    @Schema(example = "150", description = "If the time between a user clicks on the 'I want to Sign' button and the moment he signs the document is" +
            " greater than the number of seconds defined by “signTimeout” the signature will be rejected.<BR>Default value : 120 Seconds.")
    private Integer signTimeout;
    @Schema(example = "true", description = "If “true”, the user will not be allowed to download the signed file")
    private boolean noDownload;
    @Schema(description = "A list of Belgian National numbers that are allowed to sign the document")
    private List<AllowedToSign> allowedToSign;
    @Schema(example = "http://policy.hom.com/policy", description = "Only for XML documents. If present it will be added to the signature.")
    private String policyId;
    @Schema(example = "Belgium signing Policy", description = "Only for XML documents. If present it will be added to the signature.")
    private String policyDescription;
    @Schema(example = "SHA512", description = "The digest algorithm used to make the policy digest. Only for XML documents. If present it will be added to the signature.")
    private String policyDigestAlgorithm;
    @Schema(example = "true", description = "If “true”, display a 'I have read this document' checkbox to the sign user interface that must be checked before signing is allowed")
    private boolean requestDocumentReadConfirm;
}
