/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 *
 * @author wouter
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class DocumentMetadataDTO {
    private SigningType signingType;
    private boolean noSignedDownloads;
    private boolean selectDocuments;
    private boolean requestDocumentReadConfirm;
    private boolean previewDocuments; // If true, display documents in the sign screen, otherwise provide list of downloadable links
    private boolean noSkipErrors; // If true, disable the user to skip a file in error to sign

    private List<SignInputMetadata> inputs;
}
