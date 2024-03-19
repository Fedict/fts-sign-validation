package com.bosa.signandvalidation.service;

import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.enumerations.X520Attributes;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import javax.security.auth.x500.X500Principal;

public class CertInfo {
    private final String subjectName;

    public CertInfo(RemoteCertificate signingCert) {
        try {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509")
                    .generateCertificate(new ByteArrayInputStream(signingCert.getEncodedCertificate()));

            // countryName=BE,surname=TestLongNames,givenName=Christian,serialNumber=73040102750,commonName=Christian TestLongNames
            subjectName = cert.getSubjectX500Principal().getName(X500Principal.RFC2253, X520Attributes.getOidDescriptions());
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String getField(Field field) {
        int idx = subjectName.indexOf(field.name() + "=");
        if (-1 == idx)
            return "?";
        idx += field.name().length() + 1;
        int end = subjectName.indexOf(",", idx);
        return -1 == end ? subjectName.substring(idx) : subjectName.substring(idx, end);
    }

    public enum Field {
        surname, givenName, serialNumber, commonName, countryName
    }
}
