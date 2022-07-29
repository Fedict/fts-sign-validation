package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignInput {
    private String filePath; // Path of the file in the bucket to Sign (XML/PDF/Other)

    // Only for XADES Multifile
    private String xmlEltId; // The XML element where the file will be stored

    // Only when "fileName" file is of type XML
    private String displayXsltPath; // An optional XSLT filename in the bucket can be provided to display the XML

}
