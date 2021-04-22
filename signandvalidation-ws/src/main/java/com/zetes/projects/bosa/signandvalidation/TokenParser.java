/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.SecretKey;

/**
 *
 * @author wouter
 */
public class TokenParser {
    private final String cid;
    private final String in;
    private final String out;
    private final String prof;
    private final Date iad;
        
    private static JWTClaimsSet ParseToken(String token, ObjectStorageService os) throws ParseException, JOSEException, ObjectStorageService.InvalidKeyConfigException {
        JWEObject jweObject = JWEObject.parse(token);
        JWEHeader header = jweObject.getHeader();
        SecretKey key = os.getKeyForId(header.getKeyID());
        jweObject.decrypt(new DirectDecrypter(key));
        PlainJWT jwt = PlainJWT.parse(jweObject.getPayload().toString());
        return jwt.getJWTClaimsSet();
    }
        
    public TokenParser(String token, ObjectStorageService os) throws JOSEException, ParseException, ObjectStorageService.InvalidKeyConfigException {
        JWTClaimsSet claims = ParseToken(token, os);
        cid = claims.getClaim("cid").toString();
        in = claims.getClaim("in").toString();
        out = claims.getClaim("out").toString();
        prof = claims.getClaim("prof").toString();
        iad = claims.getIssueTime();
    }
    public TokenParser(String token, ObjectStorageService os, int validMinutes) throws TokenExpiredException, ParseException, JOSEException, ObjectStorageService.InvalidKeyConfigException {
        JWTClaimsSet claims = ParseToken(token, os);
        Date d = claims.getIssueTime();
        Calendar c = Calendar.getInstance();
        c.setTime(d);
        c.add(Calendar.MINUTE, validMinutes);
        Calendar now = Calendar.getInstance();
        if(c.compareTo(now) < 0) {
            throw new TokenExpiredException();
        }
        cid = claims.getClaim("cid").toString();
        in = claims.getClaim("in").toString();
        out = claims.getClaim("out").toString();
        prof = claims.getClaim("prof").toString();
        iad = d;
    }
    public String getCid() {
        return cid;
    }
    public String getIn() {
        return in;
    }
    public String getOut() {
        return out;
    }
    public String getProf() {
        return prof;
    }
    public Date getIad() {
        return iad;
    }

    public static class TokenExpiredException extends Exception {

        public TokenExpiredException() {
        }
    }
}
