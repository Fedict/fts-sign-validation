package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
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
    @Schema(example = "XADES_JUSTACT_CITIZEN", requiredMode = Schema.RequiredMode.REQUIRED, description = "The signing profile to use")
    private String signingProfileId;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A file to be signed")
    private RemoteDocument toSignDocument;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Signature parameters")
    private ClientSignatureParameters clientSignatureParameters;
    @Schema(description = "A policy to include in the signed XML file")
    private PolicyDTO policy;
    @Schema(description = "The list of XML elements Ids that must be signed")
    private List<String> elementIdsToSign;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The signed digest (from getDataToSign)")
    private byte[] signatureValue;
    @Schema(description = "A logging identifier for the current user session")
    private String token;
}
