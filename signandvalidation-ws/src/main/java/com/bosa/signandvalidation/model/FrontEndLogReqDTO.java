/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.bosa.signandvalidation.exceptions.Utils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

import java.util.logging.Level;

/**
 *
 * @author wouter
 */
@Data
public class FrontEndLogReqDTO {
    private String message;
    private String token;
    private String level;

    @JsonIgnore
    public Level getLevelEnum() {
        return Level.parse(level);
    }

    public void sanitize() {
        message             = Utils.sanitize(message, 256);
    }
}
