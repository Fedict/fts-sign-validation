package com.zetes.projects.bosa.signingconfigurator.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

import java.util.List;

// parameters which are hardcoded
public class DefaultSignatureParameters {

    private boolean trustAnchorBPPolicy = true;

    private String policyId;
    private String policyQualifier;
    private String policyDescription;
    private DigestAlgorithm policyDigestAlgorithm;
    private byte[] policyDigestValue;
    private String policySpuri;

    private List<String> commitmentTypeIndications;

    private boolean signWithExpiredCertificate = false;

    private boolean generateTBSWithoutCertificate = false;

    private RemoteTimestampParameters contentTimestampParameters;

    private RemoteTimestampParameters signatureTimestampParameters;

    private RemoteTimestampParameters archiveTimestampParameters;

    public DefaultSignatureParameters() {
    }

    public RemoteTimestampParameters getContentTimestampParameters() {
        if (contentTimestampParameters == null) {
            contentTimestampParameters = new RemoteTimestampParameters();
        }
        return contentTimestampParameters;
    }

    public void setContentTimestampParameters(RemoteTimestampParameters contentTimestampParameters) {
        this.contentTimestampParameters = contentTimestampParameters;
    }

    public RemoteTimestampParameters getSignatureTimestampParameters() {
        if (signatureTimestampParameters == null) {
            signatureTimestampParameters = new RemoteTimestampParameters();
        }
        return signatureTimestampParameters;
    }

    public void setSignatureTimestampParameters(RemoteTimestampParameters signatureTimestampParameters) {
        this.signatureTimestampParameters = signatureTimestampParameters;
    }

    public RemoteTimestampParameters getArchiveTimestampParameters() {
        if (archiveTimestampParameters == null) {
            archiveTimestampParameters = new RemoteTimestampParameters();
        }
        return archiveTimestampParameters;
    }

    public void setArchiveTimestampParameters(RemoteTimestampParameters archiveTimestampParameters) {
        this.archiveTimestampParameters = archiveTimestampParameters;
    }

    public boolean isSignWithExpiredCertificate() {
        return signWithExpiredCertificate;
    }

    public void setSignWithExpiredCertificate(final boolean signWithExpiredCertificate) {
        this.signWithExpiredCertificate = signWithExpiredCertificate;
    }

    public boolean isGenerateTBSWithoutCertificate() {
        return generateTBSWithoutCertificate;
    }

    public void setGenerateTBSWithoutCertificate(final boolean generateTBSWithoutCertificate) {
        this.generateTBSWithoutCertificate = generateTBSWithoutCertificate;
    }

    public boolean isTrustAnchorBPPolicy() {
        return trustAnchorBPPolicy;
    }

    public void setTrustAnchorBPPolicy(boolean trustAnchorBPPolicy) {
        this.trustAnchorBPPolicy = trustAnchorBPPolicy;
    }

    public String getPolicyId() {
        return policyId;
    }

    public void setPolicyId(final String id) {
        this.policyId = id;
    }

    public String getPolicyQualifier() {
        return policyQualifier;
    }

    public void setPolicyQualifier(String qualifier) {
        this.policyQualifier = qualifier;
    }

    public String getPolicyDescription() {
        return policyDescription;
    }

    public void setPolicyDescription(String description) {
        this.policyDescription = description;
    }

    public DigestAlgorithm getPolicyDigestAlgorithm() {
        return policyDigestAlgorithm;
    }

    public void setPolicyDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
        this.policyDigestAlgorithm = digestAlgorithm;
    }

    public byte[] getPolicyDigestValue() {
        return policyDigestValue;
    }

    public void setPolicyDigestValue(final byte[] digestValue) {
        this.policyDigestValue = digestValue;
    }

    public String getPolicySpuri() {
        return policySpuri;
    }

    public void setPolicySpuri(String spuri) {
        this.policySpuri = spuri;
    }

    public List<String> getCommitmentTypeIndications() {
        return commitmentTypeIndications;
    }

    public void setCommitmentTypeIndications(List<String> commitmentTypeIndications) {
        this.commitmentTypeIndications = commitmentTypeIndications;
    }

}
