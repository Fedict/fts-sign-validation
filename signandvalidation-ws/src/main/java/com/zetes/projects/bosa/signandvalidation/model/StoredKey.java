/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author wouter
 */
public class StoredKey {
    private SecretKey data;
    private String kid;

    private Date validUntil;

    public StoredKey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        data = keygen.generateKey();
        Date generated = new Date();
        byte[] kidBytes = new byte[9];
        new SecureRandom().nextBytes(kidBytes);
        kid = Base64.getUrlEncoder().encodeToString(kidBytes);
        Calendar cal = Calendar.getInstance();
        cal.setTime(generated);
        cal.add(Calendar.HOUR, 5);
        validUntil = cal.getTime();
    }

    @JsonIgnore
    public SecretKey getData() {
        return data;
    }
    public void setData(SecretKey data) {
        this.data = data;
    }
    public byte[] getEncoded() {
        return data.getEncoded();
    }
    public void setEncoded(byte[] encoded) {
        setData(new SecretKeySpec(encoded, "AES"));
    }
    public String getKid() {
        return kid;
    }
    public void setKid(String kid) {
        this.kid = kid;
    }
    public Date getValidUntil() {
        return validUntil;
    }
    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }
    @JsonIgnore
    public boolean isTooOld() {
        return validUntil.before(new Date());
    }
}
