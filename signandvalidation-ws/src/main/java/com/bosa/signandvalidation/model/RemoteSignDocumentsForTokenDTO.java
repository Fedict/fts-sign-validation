/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 *
 * @author christian
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RemoteSignDocumentsForTokenDTO {
    private String token;
    private String code;
    private byte [] photo;
    private List<InputToSign> inputsToSign;
}
