package com.zetes.projects.bosa.signingconfigurator.model;

import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

// parameters which are passed by the front-end
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

    public ClientSignatureParameters() {
    }

    public RemoteCertificate getSigningCertificate() {
        return signingCertificate;
    }

    public void setSigningCertificate(RemoteCertificate signingCertificate) {
        this.signingCertificate = signingCertificate;
    }

    public List<RemoteCertificate> getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(List<RemoteCertificate> certificateChain) {
        this.certificateChain = certificateChain;
    }

    public List<RemoteDocument> getDetachedContents() {
        return detachedContents;
    }

    public void setDetachedContents(List<RemoteDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

    public Date getSigningDate() {
        return signingDate;
    }

    public void setSigningDate(final Date signingDate) {
        this.signingDate = signingDate;
    }

    public void setClaimedSignerRoles(List<String> claimedSignerRoles) {
        this.claimedSignerRoles = claimedSignerRoles;
    }

    public List<String> getClaimedSignerRoles() {
        return claimedSignerRoles;
    }

    public String getSignerLocationCountry() {
        return signerLocationCountry;
    }

    public void setSignerLocationCountry(final String country) {
        this.signerLocationCountry = country;
    }

    public String getSignerLocationLocality() {
        return signerLocationLocality;
    }

    public void setSignerLocationLocality(final String locality) {
        this.signerLocationLocality = locality;
    }

    public List<String> getSignerLocationPostalAddress() {
        return signerLocationPostalAddress;
    }

    public void setSignerLocationPostalAddress(final List<String> postalAddress) {
        this.signerLocationPostalAddress = postalAddress;
    }

    public String getSignerLocationPostalCode() {
        return signerLocationPostalCode;
    }

    public void setSignerLocationPostalCode(String postalCode) {
        this.signerLocationPostalCode = postalCode;
    }

    public String getSignerLocationStateOrProvince() {
        return signerLocationStateOrProvince;
    }

    public void setSignerLocationStateOrProvince(String stateOrProvince) {
        this.signerLocationStateOrProvince = stateOrProvince;
    }

    public String getSignerLocationStreet() {
        return signerLocationStreet;
    }

    public void setSignerLocationStreet(String street) {
        this.signerLocationStreet = street;
    }

    public byte[] getPhoto() {
        return photo;
    }

    public void setPhoto(byte[] photo) {
        this.photo = photo;
    }
}
