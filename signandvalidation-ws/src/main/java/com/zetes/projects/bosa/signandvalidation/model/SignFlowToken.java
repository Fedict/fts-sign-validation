/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

import com.zetes.projects.bosa.signingconfigurator.model.PolicyParameters;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;
import java.util.List;

/**
 *
 * @author cmo
 */
@Setter
@Getter
@NoArgsConstructor
public class SignFlowToken {
    private CreateSignFlowDTO csf;
    private long createTime = new Date().getTime();

    public SignFlowToken(CreateSignFlowDTO csf) {
        this.csf = csf;
    }

    public boolean isValid(int minutesValid) {
        return new Date().getTime() < (createTime + minutesValid * 60000);
    }
}