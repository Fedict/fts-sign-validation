package com.zetes.projects.bosa.signingconfigurator.service;

import com.zetes.projects.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.DefaultSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SigningConfiguratorService {

    @Autowired
    ProfileSignatureParametersDao dao;

    private static final DefaultSignatureParameters defaultParams = new DefaultSignatureParameters();

    public RemoteSignatureParameters getSignatureParameters(String profileId, ClientSignatureParameters clientParams) throws ProfileNotFoundException, NullParameterException {
        if (profileId == null || clientParams == null || clientParams.getSigningCertificate() == null || clientParams.getSigningDate() == null) {
            throw new NullParameterException("Parameters should not be null");
        }

        ProfileSignatureParameters profileParams = findProfileParamsById(profileId);
        return fillRemoteSignatureParameters(clientParams, profileParams);
    }

    public RemoteSignatureParameters getSignatureParametersDefaultProfile(ClientSignatureParameters clientParams) throws ProfileNotFoundException, NullParameterException {
        if (clientParams == null || clientParams.getSigningCertificate() == null || clientParams.getSigningDate() == null) {
            throw new NullParameterException("Parameters should not be null");
        }

        ProfileSignatureParameters profileParams = findDefaultProfileParams();
        return fillRemoteSignatureParameters(clientParams, profileParams);
    }

    public RemoteSignatureParameters getExtensionParameters(String profileId, List<RemoteDocument> detachedContents) throws ProfileNotFoundException, NullParameterException {
        if (profileId == null) {
            throw new NullParameterException("Profile id should not be null");
        }

        ProfileSignatureParameters profileParams = findProfileParamsById(profileId);
        return fillExtensionParameters(detachedContents, profileParams);
    }

    public RemoteSignatureParameters getExtensionParametersDefaultProfile(List<RemoteDocument> detachedContents) throws ProfileNotFoundException {
        ProfileSignatureParameters profileParams = findDefaultProfileParams();
        return fillExtensionParameters(detachedContents, profileParams);
    }

    private RemoteSignatureParameters fillRemoteSignatureParameters(ClientSignatureParameters clientParams, ProfileSignatureParameters profileParams) {
        RemoteSignatureParameters remoteSignatureParameters = new RemoteSignatureParameters();
        RemoteBLevelParameters remoteBLevelParameters = new RemoteBLevelParameters();

        fillDefaultParams(remoteSignatureParameters, remoteBLevelParameters);
        fillProfileParams(profileParams, remoteSignatureParameters);
        fillClientParams(clientParams, remoteSignatureParameters, remoteBLevelParameters);

        remoteSignatureParameters.setBLevelParams(remoteBLevelParameters);

        return remoteSignatureParameters;
    }

    private RemoteSignatureParameters fillExtensionParameters(List<RemoteDocument> detachedContents, ProfileSignatureParameters profileParams) {
        RemoteSignatureParameters remoteSignatureParameters = new RemoteSignatureParameters();
        RemoteBLevelParameters remoteBLevelParameters = new RemoteBLevelParameters();

        fillDefaultParams(remoteSignatureParameters, remoteBLevelParameters);
        fillProfileParams(profileParams, remoteSignatureParameters);
        remoteSignatureParameters.setDetachedContents(detachedContents);

        remoteSignatureParameters.setBLevelParams(remoteBLevelParameters);

        return remoteSignatureParameters;
    }

    private void fillDefaultParams(RemoteSignatureParameters remoteSignatureParameters, RemoteBLevelParameters remoteBLevelParameters) {
        remoteSignatureParameters.setContentTimestampParameters(defaultParams.getContentTimestampParameters());
        remoteSignatureParameters.setSignatureTimestampParameters(defaultParams.getSignatureTimestampParameters());
        remoteSignatureParameters.setArchiveTimestampParameters(defaultParams.getArchiveTimestampParameters());
        remoteSignatureParameters.setSignWithExpiredCertificate(defaultParams.isSignWithExpiredCertificate());
        remoteSignatureParameters.setGenerateTBSWithoutCertificate(defaultParams.isGenerateTBSWithoutCertificate());

        remoteBLevelParameters.setTrustAnchorBPPolicy(defaultParams.isTrustAnchorBPPolicy());
        remoteBLevelParameters.setPolicyId(defaultParams.getPolicyId());
        remoteBLevelParameters.setPolicyQualifier(defaultParams.getPolicyQualifier());
        remoteBLevelParameters.setPolicyDescription(defaultParams.getPolicyDescription());
        remoteBLevelParameters.setPolicyDigestAlgorithm(defaultParams.getPolicyDigestAlgorithm());
        remoteBLevelParameters.setPolicyDigestValue(defaultParams.getPolicyDigestValue());
        remoteBLevelParameters.setPolicySpuri(defaultParams.getPolicySpuri());
        remoteBLevelParameters.setCommitmentTypeIndications(defaultParams.getCommitmentTypeIndications());
    }

    private void fillProfileParams(ProfileSignatureParameters profileParams, RemoteSignatureParameters remoteSignatureParameters) {
        remoteSignatureParameters.setAsicContainerType(profileParams.getAsicContainerType());
        remoteSignatureParameters.setSignatureLevel(profileParams.getSignatureLevel());
        remoteSignatureParameters.setSignaturePackaging(profileParams.getSignaturePackaging());
        remoteSignatureParameters.setDigestAlgorithm(profileParams.getSignatureAlgorithm().getDigestAlgorithm());
        remoteSignatureParameters.setEncryptionAlgorithm(profileParams.getSignatureAlgorithm().getEncryptionAlgorithm());
        remoteSignatureParameters.setMaskGenerationFunction(profileParams.getSignatureAlgorithm().getMaskGenerationFunction());
        remoteSignatureParameters.setReferenceDigestAlgorithm(profileParams.getReferenceDigestAlgorithm());
    }

    private void fillClientParams(ClientSignatureParameters clientParams, RemoteSignatureParameters remoteSignatureParameters, RemoteBLevelParameters remoteBLevelParameters) {
        remoteSignatureParameters.setSigningCertificate(clientParams.getSigningCertificate());
        remoteSignatureParameters.setCertificateChain(clientParams.getCertificateChain());
        remoteSignatureParameters.setDetachedContents(clientParams.getDetachedContents());

        remoteBLevelParameters.setSigningDate(clientParams.getSigningDate());
        remoteBLevelParameters.setClaimedSignerRoles(clientParams.getClaimedSignerRoles());
        remoteBLevelParameters.setSignerLocationPostalAddress(clientParams.getSignerLocationPostalAddress());
        remoteBLevelParameters.setSignerLocationPostalCode(clientParams.getSignerLocationPostalCode());
        remoteBLevelParameters.setSignerLocationLocality(clientParams.getSignerLocationLocality());
        remoteBLevelParameters.setSignerLocationStateOrProvince(clientParams.getSignerLocationStateOrProvince());
        remoteBLevelParameters.setSignerLocationCountry(clientParams.getSignerLocationCountry());
        remoteBLevelParameters.setSignerLocationStreet(clientParams.getSignerLocationStreet());
    }

    private ProfileSignatureParameters findProfileParamsById(String profileId) throws ProfileNotFoundException {
        return dao.findById(profileId).orElseThrow(() -> new ProfileNotFoundException(String.format("%s not found", profileId)));
    }

    private ProfileSignatureParameters findDefaultProfileParams() throws ProfileNotFoundException {
        return dao.findDefault().orElseThrow(() -> new ProfileNotFoundException("Default profile not found"));
    }

}
