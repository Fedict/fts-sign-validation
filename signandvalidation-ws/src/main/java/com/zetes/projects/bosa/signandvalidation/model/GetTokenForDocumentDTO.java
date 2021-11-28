/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

import java.util.List;

/**
 *
 * @author wouter
 */
public class GetTokenForDocumentDTO {
    private String name;
    private String pwd;
    private String in;
    private String out;
    private String prof;
    private String xslt;
    private String psp;   // PDF signature parameters file name
    private String psfN;  // PDF signature field name
    private String psfC;  // PDF signature field coordinates
    private String psfP;  // Include eID photo as icon in the PDF signature field
    private String lang;
    private boolean noDownload;
    private List<AllowedToSign> allowedToSign;

    public GetTokenForDocumentDTO() {
    }
    public GetTokenForDocumentDTO(String name, String pwd, String in, String out, String prof, String xslt, String psp, String psfN, String psfC, String psfP, String lang, boolean noDownload, List<AllowedToSign> allowedToSign) {
        this.name = name;
        this.pwd = pwd;
        this.in = in;
        this.out = out;
        this.prof = prof;
        this.xslt = xslt;
        this.psp = psp;
        this.psfN = psfN;
        this.psfC = psfC;
        this.psfP = psfP;
        this.lang = lang;
        this.noDownload = noDownload;
        this.allowedToSign = allowedToSign;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getPwd() {
        return pwd;
    }
    public void setPwd(String pwd) {
        this.pwd = pwd;
    }
    public String getIn() {
        return in;
    }
    public void setIn(String in) {
        this.in = in;
    }
    public String getOut() {
        return out;
    }
    public void setOut(String out) {
        this.out = out;
    }
    public String getProf() {
        return prof;
    }
    public void setProf(String prof) {
        this.prof = prof;
    }
    public String getXslt() {
        return xslt;
    }
    public void setXslt(String xslt) {
        this.xslt = xslt;
    }
    public String getPsp() {
        return psp;
    }
    public void setPsp(String psp) {
        this.psp = psp;
    }
    public String getPsfN() {
        return psfN;
    }
    public void setPsfN(String psfN) {
        this.psfN = psfN;
    }
    public String getPsfC() {
        return psfC;
    }
    public void setPsfC(String psfC) {
        this.psfC = psfC;
    }
    public String getPsfP() {
        return psfP;
    }
    public void setPsfP(String psfP) {
        this.psfP = psfP;
    }
    public String getLang() {
        return lang;
    }
    public void setLang(String lang) {
        this.lang = lang;
    }
    public boolean getNoDownload() {
        return noDownload;
    }
    public void setNoDownload(boolean noDownload) {
        this.noDownload = noDownload;
    }
    public List<AllowedToSign> getAllowedToSign() {
        return allowedToSign;
    }
    public void setAllowedToSign(List<AllowedToSign> allowedToSign) {
        this.allowedToSign = allowedToSign;
    }
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"name\":\"").append(name)
            .append("\"noDownload\":").append(noDownload)
            .append("\"in\":\"").append(in)
            .append("\", \"out\":\"").append(out)
            .append("\", \"prof\":\"").append(prof);
        if (null != xslt)
            sb.append("\", \"xslt\":\"").append(xslt);
        if (null != psp)
            sb.append("\", \"psp\":\"").append(psp);
        if (null != psfN)
            sb.append("\", \"psfN\":\"").append(psfN);
        if (null != psfC)
            sb.append("\", \"psfC\":\"").append(psfC);
        if (null != psfP)
            sb.append("\", \"psfP\":\"").append(psfP);
        if (null != lang)
            sb.append("\", \"lang\":\"").append(lang);
        if (null != allowedToSign){
            sb.append("\", \"allowedToSign\":[");
            boolean firstItem = true;
            for (AllowedToSign allowedToSignItem : allowedToSign) {
                if (firstItem){
                    firstItem = false;
                }
                else{
                    sb.append(",");
                }
                sb.append("{\"nn\":\"").append(allowedToSignItem.getNN()).append("\"}");
            }
            sb.append("]}");
        }
        else{
            sb.append("\"}");
        }
        return sb.toString();
    }
}
