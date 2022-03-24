package com.bosa.signingconfigurator.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampContainerForm;

import javax.xml.crypto.dsig.CanonicalizationMethod;

// parameters which are retrieved from the database based on the profile id
public class ProfileTimestampParameters extends JsonObject {

    /**
     * The columns unrelated to timestamp parameters.
     */
    private String profileId;

    private Boolean isDefault;

    /**
     * The columns related to timestamp parameters.
     */
    private DigestAlgorithm digestAlgorithm;

    private String canonicalizationMethod;

    private TimestampContainerForm containerForm;

    private String tspServer;
    
    private Boolean devOnlyProfile;

    public ProfileTimestampParameters() {
    }

    /**
     * The columns unrelated to signature parameters.
     */
    @Override
    public String getProfileId() {
        return profileId;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    @Override
    public Boolean getIsDefault() {
        if(null != isDefault) {
            return isDefault;
        }
        return false;
    }

    public void setIsDefault(Boolean isDefault) {
        this.isDefault = isDefault;
    }

    /**
     * The columns related to timestamp parameters.
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm != null ? digestAlgorithm : DigestAlgorithm.SHA256;
    }

    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getCanonicalizationMethod() {
        return canonicalizationMethod != null ? canonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }

    public void setCanonicalizationMethod(String canonicalizationMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
    }

    public TimestampContainerForm getContainerForm() {
        return containerForm;
    }

    public void setContainerForm(TimestampContainerForm containerForm) {
        this.containerForm = containerForm;
    }

    public String getTspServer() {
        return tspServer;
    }

    public void setTspServer(String tspServer) {
        this.tspServer = tspServer;
    }

    public void setDevOnlyProfile(Boolean devOnlyProfile) {
        this.devOnlyProfile = devOnlyProfile;
    }

    @Override
    public Boolean getDevOnlyProfile() {
        return (devOnlyProfile == null) ? false : devOnlyProfile;
    }
}
