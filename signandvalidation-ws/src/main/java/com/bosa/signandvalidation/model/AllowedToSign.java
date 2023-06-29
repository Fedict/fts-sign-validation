package com.bosa.signandvalidation.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AllowedToSign {

    @Schema(example = "55050533154", requiredMode = Schema.RequiredMode.REQUIRED, description = "A Belgian National Number that is allowed to sign")
    private String nn;
}
