/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.bosa.signandvalidation.model.remotesign.DigestsToSign;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.fasterxml.jackson.annotation.JsonFormat;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 *
 * @author wouter
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class GetDataToSignForTokenDTO {
    private String token;
    RemoteCertificate certSign;
    List<RemoteCertificate> certChain;
    private byte [] photo;
    private List<InputToSign> inputsToSign;
}
