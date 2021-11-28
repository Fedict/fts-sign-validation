package com.zetes.projects.bosa.signandvalidation.service;

import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.enumerations.X520Attributes;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import javax.security.auth.x500.X500Principal;

public class CertInfo {
    RemoteCertificate signingCert = null;
    String subjectName = null;

    public CertInfo(RemoteCertificate signingCert) {
        this.signingCert = signingCert;
    }

    String getSurname() {
        if (null == subjectName)
            subjectName = getSubjectName(signingCert);
        return getDnField(subjectName, "surname");
    }

    String getGivenName() {
        if (null == subjectName)
            subjectName = getSubjectName(signingCert);
        return getDnField(subjectName, "givenName");
    }

    public String getRRN() {
        if (null == subjectName)
            subjectName = getSubjectName(signingCert);
        return getDnField(subjectName, "serialNumber");
    }

    private String getSubjectName(RemoteCertificate signingCert) {
        try {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509")
                .generateCertificate(new ByteArrayInputStream(signingCert.getEncodedCertificate()));
            return cert.getSubjectX500Principal().getName(X500Principal.RFC2253, X520Attributes.getOidDescriptions());
       }
       catch (Exception e) {
           throw new RuntimeException(e);
       }
    }

    private String getDnField(String dn, String name) {
        int idx = dn.indexOf(name + "=");
        if (-1 == idx)
            return "?";
        idx += name.length() + 1;
        int end = dn.indexOf(",", idx);
        return -1 == end ? dn.substring(idx) : dn.substring(idx, end);
    }
}
