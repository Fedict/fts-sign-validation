package com.bosa.signingconfigurator.model;

import com.bosa.signandvalidation.model.PdfSignatureProfile;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class ClientSignatureParameters {
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The certificate that will sign the document")
    private RemoteCertificate signingCertificate;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The parent certificates that created 'signingCertificate'")
    private List<RemoteCertificate> certificateChain = new ArrayList<>();

    @Schema(description = "For detached signatures the input files to sign")
    private List<RemoteDocument> detachedContents;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The date at which signing occurs")
    private Date signingDate;

    @Schema(description = "Not used")
    private List<String> claimedSignerRoles;

    @Schema(description = "Not used")
    private List<String> signerLocationPostalAddress = new ArrayList<>();
    @Schema(description = "Not used")
    private String signerLocationPostalCode;
    @Schema(description = "Not used")
    private String signerLocationLocality;
    @Schema(description = "Not used")
    private String signerLocationStateOrProvince;
    @Schema(description = "Not used")
    private String signerLocationCountry;
    @Schema(description = "Not used")
    private String signerLocationStreet;

    @Schema(description = "For PDF files. An image that will be placed inside a visible signature field")
    private byte[] photo;

    @Schema(example = "FleetManagerSignature", description = "The name of an existing Acroform of the PDF to sign where the signature must be rendered.")
    private String psfN;
    @Schema(example = "1,200,200,300,100", description = "The position where the visible signature signature in a PDF to sign will be placed. Format : 'Page Number,X,Y,Width,Height'. Example : '1,20,20,200,100'")
    private String psfC;
    @Schema(example = "fr", description = "The language in which the visible signature text of a PDF will be rendered")
    private String signLanguage;
    @Schema(description = "A description of how the visible signature of a PDF to sign must rendered")
    private PdfSignatureProfile psp;
}
