package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GetDataToSignMultipleDTO {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A list of files to be signed")
    private List<RemoteDocument> toSignDocuments;
    @Schema(example = "XADES_LTA", requiredMode = Schema.RequiredMode.REQUIRED, description = "The signing profile to use")
    private String signingProfileId;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Signature parameters")
    private ClientSignatureParameters clientSignatureParameters;
}
