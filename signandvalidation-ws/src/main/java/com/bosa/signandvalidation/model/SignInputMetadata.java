package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignInputMetadata {
    private String fileName; // Name of the file in the bucket to Sign (XML/PDF/Other)
    private String mimeType;

    // If "filename" file is of type : PDF
    private boolean drawSignature; // If true a visible signature can be drawn
    private boolean psfP; // If true the photo must be passed in getDataToSign and signDocument

    // If "filename" file is of type : XML
    private boolean hasDisplayXslt; // If true an XSLT was provided to display the file
}
