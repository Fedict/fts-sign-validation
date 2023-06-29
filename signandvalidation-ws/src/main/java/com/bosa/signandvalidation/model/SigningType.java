package com.bosa.signandvalidation.model;

import io.swagger.v3.oas.annotations.media.Schema;

public enum SigningType {
    @Schema(description = "Sign XML or PDF files")
    Standard,
    @Schema(description = "Given a set of XML or PDF input files, place them as base 64 elements in an output XML file and sign it as XADES INTERNALLY DETACHED")
    XadesMultiFile
}
