/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
public class RemoteGetDataToSignForTokenDTO {
    RemoteCertificate certSign;
    List<RemoteCertificate> certChain;
    private String token;
    private byte [] photo;
    private List<InputToSign> inputsToSign;
}
