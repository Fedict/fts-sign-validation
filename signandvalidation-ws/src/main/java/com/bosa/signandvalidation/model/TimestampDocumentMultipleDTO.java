package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TimestampDocumentMultipleDTO {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A list of files to timestamp")
    private List<RemoteDocument> documents;
    @Schema(example = "PROFILE_1", requiredMode = Schema.RequiredMode.REQUIRED, description = "The timestamping profile to use")
    private String profileId;
    @Schema(description = "A logging identifier for the current user session")
    private String token;
}
