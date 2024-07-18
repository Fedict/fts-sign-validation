/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 *
 * @author Christian
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RemoteSignDocumentDTO {
    private String signingProfileId;
    private String token;
    private String code;
    private String signLanguage;
    private String psfN;
    private String psfC;
    private PdfSignatureProfile psp;
    private RemoteDocument toSignDocument;
}
