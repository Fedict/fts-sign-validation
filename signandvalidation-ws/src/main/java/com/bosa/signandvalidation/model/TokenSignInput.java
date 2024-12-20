package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class TokenSignInput {
    private String filePath; // Path of the file in the bucket to Sign (XML/PDF/Other)
    private String xmlEltId; // FOR XADES Multifile ! The XML element where the file will be stored
    private String documentURI; // For XADES Detached !

    // If "filePath" file is of type : XML
    private String displayXsltPath; // An XSLT full path in the bucket can be provided to display the XML

    // If "filePath" file is of type : PDF
    private String pspFilePath;  // A file with graphical description of the signature to create the acroform signature
    private SigningLanguages signLanguage;  //  The language of the signature to create
    private String psfN;  // PDF signature field name
    private float psfNWidth; // When drawing a V1 Visible signature the width & height are needed, ...
    private float psfNHeight; // ... the preflight validation done at token creation saves the dimensions in the token store for performance
    private String psfC;  // PDF signature field coordinates
    private boolean psfP;  // Include eID photo as icon in the PDF signature field
    private boolean invisible;
}
