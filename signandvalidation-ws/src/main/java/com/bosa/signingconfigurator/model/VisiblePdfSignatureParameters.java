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
public class VisiblePdfSignatureParameters {
    @Schema(description = "An image that will be placed inside a visible signature field")
    private byte[] photo;

    @Schema(example = "FleetManagerSignature", description = "The name of an existing Acroform of the PDF to sign where the signature must be rendered.")
    private String psfN;
    @Schema(example = "1,200,200,300,100", description = "The position where the visible signature signature in a PDF to sign will be placed. Format : 'Page Number,X,Y,Width,Height'. Example : '1,20,20,200,100'")
    private String psfC;
    @Schema(example = "fr", description = "The language in which the visible signature text of a PDF will be rendered")
    private String signLanguage;
    @Schema(description = "A description of how the visible signature of a PDF to sign must rendered. " +
            "V1 visible signature draws first the text & photo image, then resizes the image to the Acroform box. V2 Draws directly into the Acroform box")
    private PdfSignatureProfile psp;

    public VisiblePdfSignatureParameters(String psfC, String psfN, String signLanguage) {
        this.psfC = psfC;
        this.psfN = psfN;
        this.signLanguage = signLanguage;
    }
}
