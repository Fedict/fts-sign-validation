package com.zetes.projects.bosa.signandvalidation.model;

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
    private boolean readConfirm; // Request the user to check a "I have read the file" box before signing
    private DisplayType display; // If true, display document

    // If "filename" file is of type : XML
    private String displayXslt; // An XSLT filename in the bucket can be provided to display the XML
}
