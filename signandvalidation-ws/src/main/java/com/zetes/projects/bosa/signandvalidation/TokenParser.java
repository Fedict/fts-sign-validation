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
    private String cid;
    private String in;
    private String out;
    private String prof;
    private Date iad;
    private String xslt;  // XSLS file name
    private String lang;  // language: en (default), nl, fr, de
    private String psp;   // PDF signature parameters file name
    private String psfN;  // PDF signature field name
    private String psfC;  // PDF signature field coordinates
    private boolean psfP = false;  // Include eID photo as icon in the PDF signature field
    private String raw;
        
    private static JWTClaimsSet ParseToken(String token, ObjectStorageService os) throws ParseException, JOSEException, ObjectStorageService.InvalidKeyConfigException {
        JWEObject jweObject = JWEObject.parse(token);
        JWEHeader header = jweObject.getHeader();
        SecretKey key = os.getKeyForId(header.getKeyID());
        jweObject.decrypt(new DirectDecrypter(key));
        PlainJWT jwt = PlainJWT.parse(jweObject.getPayload().toString());
        return jwt.getJWTClaimsSet();
    }

    public TokenParser(String token, ObjectStorageService os) throws JOSEException, ParseException, ObjectStorageService.InvalidKeyConfigException {
        raw = token;
        JWTClaimsSet claims = ParseToken(token, os);
        init(claims, os, null);
    }
    public TokenParser(String token, ObjectStorageService os, int validMinutes) throws TokenExpiredException, ParseException, JOSEException, ObjectStorageService.InvalidKeyConfigException {
        raw = token;
        JWTClaimsSet claims = ParseToken(token, os);
        Date d = claims.getIssueTime();
        Calendar c = Calendar.getInstance();
        c.setTime(d);
        c.add(Calendar.MINUTE, validMinutes);
        Calendar now = Calendar.getInstance();
        if(c.compareTo(now) < 0) {
            throw new TokenExpiredException();
        }
        init(claims, os, d);
    }
    protected void init(JWTClaimsSet claims, ObjectStorageService os, Date validity) throws JOSEException, ParseException, ObjectStorageService.InvalidKeyConfigException {
        cid = claims.getClaim("cid").toString();
        in = claims.getClaim("in").toString();
        out = claims.getClaim("out").toString();
        prof = claims.getClaim("prof").toString();
        if(claims.getClaims().containsKey("xslt")) {
            xslt = claims.getClaim("xslt").toString();
        } else {
            xslt = null;
        }
        if(claims.getClaims().containsKey("lang"))
            lang = claims.getClaim("lang").toString();
        if(claims.getClaims().containsKey("psp"))
            psp = claims.getClaim("psp").toString();
        if(claims.getClaims().containsKey("psfN"))
            psfN = claims.getClaim("psfN").toString();
        if(claims.getClaims().containsKey("psfC"))
            psfC = claims.getClaim("psfC").toString();
        if(claims.getClaims().containsKey("psfP"))
            psfP = "true".equals(claims.getClaim("psfP").toString());
        if (null != validity)
            iad = validity;
        else
            iad = claims.getIssueTime();
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
    public String getXslt() {
        return xslt;
    }
    public String getPsp() {
        return psp;
    }
    public String getLang() {
        return lang;
    }
    public String getPsfN() {
        return psfN;
    }
    public String getPsfC() {
        return psfC;
    }
    public boolean getPsfP() {
        return psfP;
    }
    public String getRaw() {
        return raw;
    }

    public static class TokenExpiredException extends Exception {

        public TokenExpiredException() {
        }
    }
}
