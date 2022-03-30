/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signingconfigurator.model;

/**
 *
 * @author wouter
 */
public abstract class JsonObject {
    public abstract Boolean getDevOnlyProfile();
    public abstract Boolean getIsDefault();
    public abstract String getProfileId();
}
