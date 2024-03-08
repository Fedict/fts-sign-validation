package com.bosa.signandvalidation.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignInput {
    @Schema(example = "inputs/ToBeSigned.xml", requiredMode = Schema.RequiredMode.REQUIRED, description = "The path of the file, stored on the S3 server, that must be signed")
    private String filePath; // Path of the file in the bucket to Sign (XML/PDF/Other)

    // Only for XADES Multifile
    @Schema(example = "ID1", description = " Only applicable to XadesMultifile signType. The XML ID to used when creating the target XML file")
    private String xmlEltId; // The XML element where the file will be stored

    // Only when "fileName" file is of type XML
    @Schema(example = "RENDER.xslt", description = " Only applicable to XML files. The name of the file, stored on the S3 server, that must be used to improve the display of the XML to be signed")
    private String displayXsltPath; // An optional XSLT filename in the bucket can be provided to display the XML

    // If "filePath" file is of type : PDF
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
    private String pspFilePath;
    @Schema(example = "en", description = "The language in which the visible signature text of a PDF will be rendered")
    private String signLanguage;
    @Schema(example = "FleetManagerSignature", description = "The name of an existing Acroform of the PDF to sign where the signature must be rendered. If set, overrides 'drawable' field.")
    private String psfN;
    @Schema(example = "1,200,200,300,100", description = "The position where the visible signature signature in a PDF to sign will be placed. Format : 'Page Number,X,Y,Width,Height'. Example : '1,20,20,200,100'. If set, overrides 'drawable' field.")
    private String psfC;
    @Schema(example = "true", description = "A boolean, if true it means the visible signature of a PDF to sign will include hte picture of the EID")
    private boolean psfP;
    @Schema(example = "true", description = "A boolean, if false it that the PDF signature will be invisible. If true it means the user can draw a signature form on the PDF, or select an existing signature form, where a visible signature will display the signature details, unless a psfC or psfN has been specified")
    private Boolean drawable;
}
