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
public class ExtendDocumentDTO {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A signed file")
    private RemoteDocument toExtendDocument;
    @Schema(example = "XADES_LTA", requiredMode = Schema.RequiredMode.REQUIRED, description = "The signing profile to reach for the file")
    private String extendProfileId;
    @Schema(description = "In case the signature is detached (and covers multiple documents) provides the original signed file data")
    private List<RemoteDocument> detachedContents;
}
