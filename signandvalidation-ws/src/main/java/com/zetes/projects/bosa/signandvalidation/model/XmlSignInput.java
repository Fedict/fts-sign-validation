package com.zetes.projects.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class XmlSignInput {
    private String fileName;
    private String targetXmlEltId;

    private String displayXslt;
    private Boolean noDownload;
    private Boolean requestDocumentReadConfirm;
}
