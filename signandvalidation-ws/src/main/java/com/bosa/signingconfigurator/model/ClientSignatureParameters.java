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

    private List<String> claimedSignerRoles;
    private List<String> signerLocationPostalAddress = new ArrayList<>();
    private String signerLocationPostalCode;
    private String signerLocationLocality;
    private String signerLocationStateOrProvince;
    private String signerLocationCountry;
    private String signerLocationStreet;

    @Schema(description = "Only used for getDataToSign, signDocument, getDataToSignForToken and signDocumentForToken used for customizing the visible PDF signature")
    private VisiblePdfSignatureParameters pdfSigParams;

    public ClientSignatureParameters(RemoteCertificate signingCertificate, List<RemoteCertificate> certificateChain, Date signingDate) {
        this.signingCertificate = signingCertificate;
        this.certificateChain = certificateChain;
        this.signingDate = signingDate;
    }
}
