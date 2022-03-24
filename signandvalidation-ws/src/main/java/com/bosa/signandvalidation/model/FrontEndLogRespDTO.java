/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

/**
 *
 * @author wouter
 */
public class FrontEndLogRespDTO {
    private String ref;

    public FrontEndLogRespDTO(String ref) {
        this.ref = ref;
    }
    public String getRef() {
        return ref;
    }
    public void setRef(String ref) {
        this.ref = ref;
    }
}
