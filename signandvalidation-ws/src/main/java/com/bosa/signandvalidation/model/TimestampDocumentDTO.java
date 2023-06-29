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
public class TimestampDocumentDTO {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A file to timestamp")
    private RemoteDocument document;
    @Schema(example = "PROFILE_1", requiredMode = Schema.RequiredMode.REQUIRED, description = "The timestamping profile to reach for the file")
    private String profileId;
}
