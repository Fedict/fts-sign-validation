package com.bosa.signingconfigurator.model;

import com.bosa.signandvalidation.model.PdfSignatureProfile;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class ClientSignatureParameters {
    private RemoteCertificate signingCertificate;
    private List<RemoteCertificate> certificateChain = new ArrayList<>();

    private List<RemoteDocument> detachedContents;

    private Date signingDate;

    private List<String> claimedSignerRoles;

    private List<String> signerLocationPostalAddress = new ArrayList<>();
    private String signerLocationPostalCode;
    private String signerLocationLocality;
    private String signerLocationStateOrProvince;
    private String signerLocationCountry;
    private String signerLocationStreet;

    private byte[] photo;

    private String psfN;
    private String psfC;
    private String signLanguage;
    private PdfSignatureProfile psp;
}
