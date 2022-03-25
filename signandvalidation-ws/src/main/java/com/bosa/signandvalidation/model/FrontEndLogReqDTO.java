/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.logging.Level;

/**
 *
 * @author wouter
 */
public class FrontEndLogReqDTO {
    private String message;
    private String token;
    private String level;

    public String getMessage() {
        return message;
    }
    public String getToken() {
        return token;
    }
    public String getLevel() {
        return level;
    }
    public void setMessage(String message) {
        this.message = message;
    }
    public void setToken(String token) {
        this.token = token;
    }
    public void setLevel(String level) {
        this.level = level;
    }

    @JsonIgnore
    public Level getLevelEnum() {
        return Level.parse(level);
    }
}
