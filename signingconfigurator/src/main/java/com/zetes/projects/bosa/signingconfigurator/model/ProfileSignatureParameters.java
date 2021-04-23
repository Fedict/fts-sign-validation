package com.zetes.projects.bosa.signingconfigurator.model;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
import java.util.List;

// parameters which are retrieved from the database based on the profile id
public class ProfileSignatureParameters {

    /**
     * The columns unrelated to signature parameters.
     */
    private String profileId;

    /*@Column(nullable = false, updatable = false)
    private Instant created;

    @Column(nullable = false)
    private Instant updated;*/

    private Boolean isDefault;

    /**
     * The columns related to signature parameters.
     */
    private ASiCContainerType asicContainerType;

    private SignatureLevel signatureLevel;

    private SignaturePackaging signaturePackaging;

    private DigestAlgorithm digestAlgorithm;

    private MaskGenerationFunction maskGenerationFunction;

    private DigestAlgorithm referenceDigestAlgorithm;

    /**
     * Overridable default parameters
     */
    private Boolean trustAnchorBPPolicy;

    private String policyId;

    private String policyQualifier;

    private String policyDescription;

    private DigestAlgorithm policyDigestAlgorithm;

    private byte[] policyDigestValue;

    private String policySpuri;

    private List<String> commitmentTypeIndications = new ArrayList<>();

    private Boolean signWithExpiredCertificate;

    private Boolean generateTBSWithoutCertificate;

    private DigestAlgorithm contentTimestampDigestAlgorithm;

    private String contentTimestampCanonicalizationMethod;

    private TimestampContainerForm contentTimestampContainerForm;

    private DigestAlgorithm signatureTimestampDigestAlgorithm;

    private String signatureTimestampCanonicalizationMethod;

    private TimestampContainerForm signatureTimestampContainerForm;

    private DigestAlgorithm archiveTimestampDigestAlgorithm;

    private String archiveTimestampCanonicalizationMethod;

    private TimestampContainerForm archiveTimestampContainerForm;

    private String tspServer;

    public ProfileSignatureParameters() {
    }

    /*
     * The values unrelated to signature parameters.
     */
    public String getProfileId() {
        return profileId;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    public Boolean getIsDefault() {
        return (isDefault == null) ? false : isDefault;
    }

    public void setIsDefault(Boolean isDefault) {
        this.isDefault = isDefault;
    }

    /*
     * The values related to signature parameters.
     */
    public ASiCContainerType getAsicContainerType() {
        return asicContainerType;
    }

    public void setAsicContainerType(ASiCContainerType asicContainerType) {
        this.asicContainerType = asicContainerType;
    }

    public SignatureLevel getSignatureLevel() {
        return signatureLevel;
    }

    public void setSignatureLevel(final SignatureLevel signatureLevel) {
        if (signatureLevel == null) {
            throw new NullPointerException("signatureLevel");
        }
        this.signatureLevel = signatureLevel;
    }

    public DigestAlgorithm getReferenceDigestAlgorithm() {
        return referenceDigestAlgorithm;
    }

    public void setReferenceDigestAlgorithm(DigestAlgorithm referenceDigestAlgorithm) {
        this.referenceDigestAlgorithm = referenceDigestAlgorithm;
    }

    public SignaturePackaging getSignaturePackaging() {
        return signaturePackaging;
    }

    public void setSignaturePackaging(final SignaturePackaging signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public MaskGenerationFunction getMaskGenerationFunction() {
        return maskGenerationFunction;
    }

    public void setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
        this.maskGenerationFunction = maskGenerationFunction;
    }

    public Boolean getTrustAnchorBPPolicy() {
        return trustAnchorBPPolicy != null ? trustAnchorBPPolicy : true;
    }

    public void setTrustAnchorBPPolicy(Boolean trustAnchorBPPolicy) {
        this.trustAnchorBPPolicy = trustAnchorBPPolicy;
    }

    public String getPolicyId() {
        return policyId;
    }

    public void setPolicyId(String policyId) {
        this.policyId = policyId;
    }

    public String getPolicyQualifier() {
        return policyQualifier;
    }

    public void setPolicyQualifier(String policyQualifier) {
        this.policyQualifier = policyQualifier;
    }

    public String getPolicyDescription() {
        return policyDescription;
    }

    public void setPolicyDescription(String policyDescription) {
        this.policyDescription = policyDescription;
    }

    public DigestAlgorithm getPolicyDigestAlgorithm() {
        return policyDigestAlgorithm;
    }

    public void setPolicyDigestAlgorithm(DigestAlgorithm policyDigestAlgorithm) {
        this.policyDigestAlgorithm = policyDigestAlgorithm;
    }

    public byte[] getPolicyDigestValue() {
        return policyDigestValue;
    }

    public void setPolicyDigestValue(byte[] policyDigestValue) {
        this.policyDigestValue = policyDigestValue;
    }

    public String getPolicySpuri() {
        return policySpuri;
    }

    public void setPolicySpuri(String policySpuri) {
        this.policySpuri = policySpuri;
    }

    public List<String> getCommitmentTypeIndications() {
        return commitmentTypeIndications;
    }

    public void setCommitmentTypeIndications(List<String> commitmentTypeIndications) {
        this.commitmentTypeIndications = commitmentTypeIndications;
    }

    public Boolean getSignWithExpiredCertificate() {
        return signWithExpiredCertificate != null ? signWithExpiredCertificate : false;
    }

    public void setSignWithExpiredCertificate(Boolean signWithExpiredCertificate) {
        this.signWithExpiredCertificate = signWithExpiredCertificate;
    }

    public Boolean getGenerateTBSWithoutCertificate() {
        return generateTBSWithoutCertificate != null ? generateTBSWithoutCertificate : false;
    }

    public void setGenerateTBSWithoutCertificate(Boolean generateTBSWithoutCertificate) {
        this.generateTBSWithoutCertificate = generateTBSWithoutCertificate;
    }

    public DigestAlgorithm getContentTimestampDigestAlgorithm() {
        return contentTimestampDigestAlgorithm != null ? contentTimestampDigestAlgorithm : DigestAlgorithm.SHA256;
    }

    public void setContentTimestampDigestAlgorithm(DigestAlgorithm contentTimestampDigestAlgorithm) {
        this.contentTimestampDigestAlgorithm = contentTimestampDigestAlgorithm;
    }

    public String getContentTimestampCanonicalizationMethod() {
        return contentTimestampCanonicalizationMethod != null ? contentTimestampCanonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }

    public void setContentTimestampCanonicalizationMethod(String contentTimestampCanonicalizationMethod) {
        this.contentTimestampCanonicalizationMethod = contentTimestampCanonicalizationMethod;
    }

    public TimestampContainerForm getContentTimestampContainerForm() {
        return contentTimestampContainerForm;
    }

    public void setContentTimestampContainerForm(TimestampContainerForm contentTimestampContainerForm) {
        this.contentTimestampContainerForm = contentTimestampContainerForm;
    }

    // combine ContentTimestampParameters
    public RemoteTimestampParameters getContentTimestampParameters() {
        return new RemoteTimestampParameters(getContentTimestampContainerForm(), getContentTimestampDigestAlgorithm(), getContentTimestampCanonicalizationMethod());
    }

    public DigestAlgorithm getSignatureTimestampDigestAlgorithm() {
        return signatureTimestampDigestAlgorithm != null ? signatureTimestampDigestAlgorithm : DigestAlgorithm.SHA256;
    }

    public void setSignatureTimestampDigestAlgorithm(DigestAlgorithm signatureTimestampDigestAlgorithm) {
        this.signatureTimestampDigestAlgorithm = signatureTimestampDigestAlgorithm;
    }

    public String getSignatureTimestampCanonicalizationMethod() {
        return signatureTimestampCanonicalizationMethod != null ? signatureTimestampCanonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }

    public void setSignatureTimestampCanonicalizationMethod(String signatureTimestampCanonicalizationMethod) {
        this.signatureTimestampCanonicalizationMethod = signatureTimestampCanonicalizationMethod;
    }

    public TimestampContainerForm getSignatureTimestampContainerForm() {
        return signatureTimestampContainerForm;
    }

    public void setSignatureTimestampContainerForm(TimestampContainerForm signatureTimestampContainerForm) {
        this.signatureTimestampContainerForm = signatureTimestampContainerForm;
    }

    // combine SignatureTimestampParameters
    public RemoteTimestampParameters getSignatureTimestampParameters() {
        return new RemoteTimestampParameters(getSignatureTimestampContainerForm(), getSignatureTimestampDigestAlgorithm(), getSignatureTimestampCanonicalizationMethod());
    }

    public DigestAlgorithm getArchiveTimestampDigestAlgorithm() {
        return archiveTimestampDigestAlgorithm != null ? archiveTimestampDigestAlgorithm : DigestAlgorithm.SHA256;
    }

    public void setArchiveTimestampDigestAlgorithm(DigestAlgorithm archiveTimestampDigestAlgorithm) {
        this.archiveTimestampDigestAlgorithm = archiveTimestampDigestAlgorithm;
    }

    public String getArchiveTimestampCanonicalizationMethod() {
        return archiveTimestampCanonicalizationMethod != null ? archiveTimestampCanonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }

    public void setArchiveTimestampCanonicalizationMethod(String archiveTimestampCanonicalizationMethod) {
        this.archiveTimestampCanonicalizationMethod = archiveTimestampCanonicalizationMethod;
    }

    public TimestampContainerForm getArchiveTimestampContainerForm() {
        return archiveTimestampContainerForm;
    }

    public void setArchiveTimestampContainerForm(TimestampContainerForm archiveTimestampContainerForm) {
        this.archiveTimestampContainerForm = archiveTimestampContainerForm;
    }

    // combine ArchiveTimestampParameters
    public RemoteTimestampParameters getArchiveTimestampParameters() {
        return new RemoteTimestampParameters(getArchiveTimestampContainerForm(), getArchiveTimestampDigestAlgorithm(), getArchiveTimestampCanonicalizationMethod());
    }

    public String getTspServer() {
        return tspServer;
    }

    public void setTspServer(String tspServer) {
        this.tspServer = tspServer;
    }
}
