/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ConsentForTokenDTO {
    private String token;
    private String signLanguage;
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss.SSSZ")
    private Date signingDate;
    private List<InputToBeSigned> signedInputs;
    private RemoteCertificate signingCertificate;
    private List<RemoteCertificate> certificateChain;
    private List<byte []> signatures;
}
