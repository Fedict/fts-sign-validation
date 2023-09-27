package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GetDataToSignDTO {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A file to be signed")
    private RemoteDocument toSignDocument;
    @Schema(example = "XADES_LTA", requiredMode = Schema.RequiredMode.REQUIRED, description = "The signing profile to use")
    private String signingProfileId;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Signature parameters")
    private ClientSignatureParameters clientSignatureParameters;
    @Schema(description = "A logging identifier for the current user session")
    private String token;
}
