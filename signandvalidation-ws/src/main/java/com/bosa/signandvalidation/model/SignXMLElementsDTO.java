package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.model.PolicyParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignXMLElementsDTO {
    @Schema(example = "XADES_MDOC_LTA", requiredMode = Schema.RequiredMode.REQUIRED, description = "The signing profile to use")
    private String signingProfileId;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A file to be signed")
    private RemoteDocument toSignDocument;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Signature parameters")
    private ClientSignatureParameters clientSignatureParameters;
    @Schema(description = "A policy to include in the signed XML file")
    private PolicyParameters policy;
    @Schema(description = "The list of XML elements that must be signed")
    private List<SignElement> elementsToSign;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The signed digest (from getDataToSign)")
    private byte[] signatureValue;
}
