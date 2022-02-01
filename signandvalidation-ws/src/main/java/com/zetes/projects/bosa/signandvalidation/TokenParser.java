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
import com.zetes.projects.bosa.signandvalidation.model.GetTokenForDocumentDTO;
import com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService;
import lombok.Getter;

import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

/**
 *
 * @author wouter
 */
@Getter
public class TokenParser {
    GetTokenForDocumentDTO token;
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
    private Boolean psfP = false;  // Include eID photo as icon in the PDF signature field
    private Boolean noDownload;
    private Integer signTimeout;
    private String raw;
    private List<String> allowedToSign;
    private String policyId; // EPES. Optional policy fields
    private String policyDescription; // EPES. Optional policy fields
    private eu.europa.esig.dss.enumerations.DigestAlgorithm policyDigestAlgorithm; // EPES. Optional policy fields
    private Boolean requestDocumentReadConfirm;

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

        noDownload = claims.getClaim("nd") == null ? false : claims.getClaim("nd").equals(true);
        requestDocumentReadConfirm = claims.getClaim("rdrc") == null ? false : claims.getClaim("rdrc").equals(true);

        if(claims.getClaims().containsKey("st"))
            signTimeout = claims.getIntegerClaim("st");

        claims.getClaims().get("st");
        if(claims.getClaims().containsKey("allowedToSign"))
            allowedToSign = claims.getStringListClaim("allowedToSign");

        // EPES. Optional policy fields
        if(claims.getClaims().containsKey("polId"))
            policyId = claims.getClaim("polId").toString();
        if(claims.getClaims().containsKey("polDesc"))
            policyDescription = claims.getClaim("polDesc").toString();
        if(claims.getClaims().containsKey("polDigAlg"))
            policyDigestAlgorithm = eu.europa.esig.dss.enumerations.DigestAlgorithm.valueOf(claims.getClaim("polDigAlg").toString());
    }

    public boolean isAllowedToSignCheckNeeded(){
        return (allowedToSign != null && allowedToSign.size() > 0);
    }
    public boolean DoAllowedToSignListContains(String nn){
        return (allowedToSign != null && allowedToSign.contains(nn));
    }

    public static class TokenExpiredException extends Exception {

        public TokenExpiredException() {
        }
    }
}
