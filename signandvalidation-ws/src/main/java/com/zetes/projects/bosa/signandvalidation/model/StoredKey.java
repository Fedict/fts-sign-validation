/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 *
 * @author wouter
 */
public class StoredKey {
    private final SecretKey data;
    private final String kid;

    private final Date validUntil;
    private final Date generated;

    public StoredKey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        data = keygen.generateKey();
        generated = new Date();
        byte[] kidBytes = new byte[10];
        new SecureRandom().nextBytes(kidBytes);
        kid = Base64.getUrlEncoder().encodeToString(kidBytes);
        Calendar cal = Calendar.getInstance();
        cal.setTime(generated);
        cal.add(Calendar.HOUR, 5);
        validUntil = cal.getTime();
    }
    public SecretKey getData() {
        return data;
    }
    public String getKid() {
        return kid;
    }
    public boolean isTooOld() {
        return validUntil.before(new Date());
    }
}
