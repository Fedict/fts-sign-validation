/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 *
 * @author wouter
 */
@Setter
@Getter
@NoArgsConstructor
public class DocumentMetadataDTO {
    private String filename;
    private String mimetype;
    private String xsltUrl;
    private boolean readPhoto;
    private boolean disallowSignedDownloads;
    private boolean requestDocumentReadConfirm;

    private List<SignInputMetadata> inputs;
    
    public DocumentMetadataDTO(String filename, String mimetype, String xsltUrl, boolean readPhoto, boolean disallowSignedDownloads, boolean requestDocumentReadConfirm, List<SignInputMetadata> inputs) {
        this.filename = filename;
        this.mimetype = mimetype;
        this.xsltUrl = xsltUrl;
        this.readPhoto = readPhoto;
        this.disallowSignedDownloads = disallowSignedDownloads;
        this.requestDocumentReadConfirm = requestDocumentReadConfirm;
        this.inputs = inputs;
    }
}
