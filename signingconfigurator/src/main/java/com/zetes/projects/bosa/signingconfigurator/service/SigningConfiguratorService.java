package com.zetes.projects.bosa.signingconfigurator.service;

import com.zetes.projects.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.exception.SignatureAlgoNotSupportedException;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.DefaultSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileSignatureParameters;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SigningConfiguratorService {

    @Autowired
    ProfileSignatureParametersDao dao;

    private static final DefaultSignatureParameters defaultParams = new DefaultSignatureParameters();

    public RemoteSignatureParameters getSignatureParameters(String profileId, ClientSignatureParameters clientParams) throws ProfileNotFoundException, SignatureAlgoNotSupportedException, NullParameterException {
        // TODO input validation service?
        if (profileId == null || clientParams == null || clientParams.getSigningCertificate() == null) {
            throw new NullParameterException("Parameters should not be null");
        }

        ProfileSignatureParameters profileParams = getProfileSignatureParameters(profileId);
        SignatureAlgorithm signatureAlgorithm = getSigningCertificateSignatureAlgorithm(clientParams.getSigningCertificate());

        if (!profileParams.getSupportedSignatureAlgorithms().contains(signatureAlgorithm)) {
            throw new SignatureAlgoNotSupportedException(
                    String.format("%s is not supported by profile %s", signatureAlgorithm.toString(), profileId)
            );
        }

        RemoteSignatureParameters remoteSignatureParameters = new RemoteSignatureParameters();

        remoteSignatureParameters.setContentTimestampParameters(defaultParams.getContentTimestampParameters());
        remoteSignatureParameters.setSignatureTimestampParameters(defaultParams.getSignatureTimestampParameters());
        remoteSignatureParameters.setArchiveTimestampParameters(defaultParams.getArchiveTimestampParameters());
        remoteSignatureParameters.setSignWithExpiredCertificate(defaultParams.isSignWithExpiredCertificate());
        remoteSignatureParameters.setGenerateTBSWithoutCertificate(defaultParams.isGenerateTBSWithoutCertificate());

        remoteSignatureParameters.setSigningCertificate(clientParams.getSigningCertificate());
        remoteSignatureParameters.setCertificateChain(clientParams.getCertificateChain());
        remoteSignatureParameters.setDetachedContents(clientParams.getDetachedContents());

        remoteSignatureParameters.setAsicContainerType(profileParams.getAsicContainerType());
        remoteSignatureParameters.setSignatureLevel(profileParams.getSignatureLevel());
        remoteSignatureParameters.setSignaturePackaging(profileParams.getSignaturePackaging());
        remoteSignatureParameters.setDigestAlgorithm(signatureAlgorithm.getDigestAlgorithm());
        remoteSignatureParameters.setEncryptionAlgorithm(signatureAlgorithm.getEncryptionAlgorithm());
        remoteSignatureParameters.setMaskGenerationFunction(signatureAlgorithm.getMaskGenerationFunction());
        remoteSignatureParameters.setReferenceDigestAlgorithm(profileParams.getReferenceDigestAlgorithm());

        // remoteBLevelParameters
        RemoteBLevelParameters remoteBLevelParameters = new RemoteBLevelParameters();

        remoteBLevelParameters.setTrustAnchorBPPolicy(defaultParams.isTrustAnchorBPPolicy());
        remoteBLevelParameters.setPolicyId(defaultParams.getPolicyId());
        remoteBLevelParameters.setPolicyQualifier(defaultParams.getPolicyQualifier());
        remoteBLevelParameters.setPolicyDescription(defaultParams.getPolicyDescription());
        remoteBLevelParameters.setPolicyDigestAlgorithm(defaultParams.getPolicyDigestAlgorithm());
        remoteBLevelParameters.setPolicyDigestValue(defaultParams.getPolicyDigestValue());
        remoteBLevelParameters.setPolicySpuri(defaultParams.getPolicySpuri());
        remoteBLevelParameters.setCommitmentTypeIndications(defaultParams.getCommitmentTypeIndications());

        remoteBLevelParameters.setSigningDate(clientParams.getSigningDate());
        remoteBLevelParameters.setClaimedSignerRoles(clientParams.getClaimedSignerRoles());
        remoteBLevelParameters.setSignerLocationPostalAddress(clientParams.getSignerLocationPostalAddress());
        remoteBLevelParameters.setSignerLocationPostalCode(clientParams.getSignerLocationPostalCode());
        remoteBLevelParameters.setSignerLocationLocality(clientParams.getSignerLocationLocality());
        remoteBLevelParameters.setSignerLocationStateOrProvince(clientParams.getSignerLocationStateOrProvince());
        remoteBLevelParameters.setSignerLocationCountry(clientParams.getSignerLocationCountry());
        remoteBLevelParameters.setSignerLocationStreet(clientParams.getSignerLocationStreet());

        remoteSignatureParameters.setBLevelParams(remoteBLevelParameters);

        return remoteSignatureParameters;
    }

    private SignatureAlgorithm getSigningCertificateSignatureAlgorithm(RemoteCertificate signingCert) {
        String sigAlgOID = DSSUtils.loadCertificate(signingCert.getEncodedCertificate()).getCertificate().getSigAlgOID();

        return SignatureAlgorithm.forOID(sigAlgOID);
    }

    private ProfileSignatureParameters getProfileSignatureParameters(String profileId) throws ProfileNotFoundException {
        return dao.findById(profileId).orElseThrow(() -> new ProfileNotFoundException(String.format("%s not found", profileId)));
    }

}
