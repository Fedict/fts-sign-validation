package com.zetes.projects.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class TokenSignInput {
    private String fileName; // Name of the file in the bucket to Sign (XML/PDF/Other)
    private String xmlEltId; // FOR XADES Multifile ! The XML element where the file will be stored
    private boolean readConfirm; // Request the user to check a "I have read the file" box before signing
    private DisplayType display; // If true, display document

    // If "filename" file is of type : XML
    private String displayXslt; // An XSLT filename in the bucket can be provided to display the XML

    // If "filename" file is of type : PDF
    private String pspFileName;  // A graphical description of the signature to create the acroform signature
    private String signLanguage;  //  The language of the signature to create
    private String psfN;  // PDF signature field name
    private String psfC;  // PDF signature field coordinates
    private boolean psfP;  // Include eID photo as icon in the PDF signature field
}
