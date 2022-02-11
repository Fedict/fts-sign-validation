package com.zetes.projects.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class XmlSignInput {
    // Name of the file to Sing (XML/PDF/Other)
    private String fileName;
    // If file is of type XML an XSLT can be provided to display the XML
    private String displayXslt;
    // The XML element where the file will be stored
    private String xmlEltId;
    // Request the user to check a "I have read the file" box before signing
    private Boolean readConfirm;
}
