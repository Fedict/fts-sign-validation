package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.SigningType;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.bosa.signingconfigurator.model.ProfileTimestampParameters;
import com.bosa.signandvalidation.SignAndValidationBaseTest;
import com.bosa.signandvalidation.config.ErrorStrings;
import com.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import com.bosa.signingconfigurator.dao.ProfileTimestampParametersDao;
import com.bosa.signingconfigurator.model.VisiblePdfSignatureParameters;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.context.ApplicationContext;

import java.util.ArrayList;
import java.util.List;

import static eu.europa.esig.dss.enumerations.DigestAlgorithm.*;
import static eu.europa.esig.dss.enumerations.TimestampContainerForm.PDF;
import static javax.xml.crypto.dsig.Transform.ENVELOPED;

public class SigningControllerBaseTest extends SignAndValidationBaseTest implements ErrorStrings {

    public enum SignProfiles {
        XADES_B,XADES_T,CADES_B,PADES_B,XADES_LTA,JADES_B, XADES_MDOC_LTA, XADES_B_DETACHED, XADES_MULTIFILE_DETACHED
    }

    @BeforeAll
    public static void fillDB(ApplicationContext applicationContext) {
        ProfileSignatureParametersDao profileSigParamDao = applicationContext.getBean(ProfileSignatureParametersDao.class);
        profileSigParamDao.deleteAll();
        saveProfileSignatureParameters(profileSigParamDao, SignProfiles.XADES_B.name(), null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPED, null, SHA256, null, null, SignatureForm.XAdES);
        saveProfileSignatureParameters(profileSigParamDao, SignProfiles.XADES_T.name(), null, SignatureLevel.XAdES_BASELINE_T,
                SignaturePackaging.ENVELOPED, null, SHA256, null, null, SignatureForm.XAdES);
        saveProfileSignatureParameters(profileSigParamDao, SignProfiles.CADES_B.name(), ASiCContainerType.ASiC_S, SignatureLevel.CAdES_BASELINE_B,
                SignaturePackaging.DETACHED, null, SHA256, null, null, SignatureForm.CAdES);
        saveProfileSignatureParameters(profileSigParamDao, SignProfiles.PADES_B.name(), null, SignatureLevel.PAdES_BASELINE_B,
                SignaturePackaging.ENVELOPED, null, SHA256, null, null, SignatureForm.PAdES);
        saveProfileSignatureParameters(profileSigParamDao, SignProfiles.XADES_LTA.name(), null, SignatureLevel.XAdES_BASELINE_LTA,
                SignaturePackaging.ENVELOPED, SHA256, SHA256, null, null, SignatureForm.XAdES);
        saveProfileSignatureParameters(profileSigParamDao, SignProfiles.JADES_B.name(), null, SignatureLevel.JAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA384, SHA384, null, null, SignatureForm.JAdES);
        saveProfileSignatureParameters(profileSigParamDao, SignProfiles.XADES_MDOC_LTA.name(), null, SignatureLevel.XAdES_BASELINE_LTA,
                SignaturePackaging.ENVELOPED, SHA512, SHA256, null, SigningType.XadesMultiFile, SignatureForm.XAdES);
        saveProfileSignatureParameters(profileSigParamDao, SignProfiles.XADES_B_DETACHED.name(), null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.DETACHED, null, SHA256, null, null, SignatureForm.XAdES);
        saveProfileSignatureParameters(profileSigParamDao, SignProfiles.XADES_MULTIFILE_DETACHED.name(), null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.DETACHED, null, SHA256, null, SigningType.MultiFileDetached, SignatureForm.XAdES);


        ProfileTimestampParametersDao timestampParamDao = applicationContext.getBean(ProfileTimestampParametersDao.class);
        timestampParamDao.deleteAll();
        saveProfileTimestampParameters(timestampParamDao, "PROFILE_1", SHA256, ENVELOPED, PDF);
    }

    protected ClientSignatureParameters getClientSignatureParameters(DSSPrivateKeyEntry dssPrivateKeyEntry) {
        List<RemoteCertificate> chain = new ArrayList<>();
        for (CertificateToken token : dssPrivateKeyEntry.getCertificateChain()) {
            chain.add(new RemoteCertificate(token.getEncoded()));
        }

        ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters();
        clientSignatureParameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getEncoded()));
        clientSignatureParameters.setCertificateChain(chain);
        clientSignatureParameters.setPdfSigParams(new VisiblePdfSignatureParameters());
        return clientSignatureParameters;
    }

    protected static void saveProfileSignatureParameters(ProfileSignatureParametersDao dao,
                                                         String profileId,
                                                         ASiCContainerType containerType,
                                                         SignatureLevel signatureLevel,
                                                         SignaturePackaging signaturePackaging,
                                                         DigestAlgorithm referenceDigestAlgorithm,
                                                         DigestAlgorithm digestAlgorithm,
                                                         MaskGenerationFunction maskGenerationFunction,
                                                         SigningType signType,
                                                         SignatureForm signatureForm) {
        ProfileSignatureParameters profileParams = new ProfileSignatureParameters();
        profileParams.setProfileId(profileId);
        profileParams.setAsicContainerType(containerType);
        profileParams.setSignatureLevel(signatureLevel);
        profileParams.setSignaturePackaging(signaturePackaging);
        profileParams.setDigestAlgorithm(digestAlgorithm);
        profileParams.setMaskGenerationFunction(maskGenerationFunction);
        profileParams.setReferenceDigestAlgorithm(referenceDigestAlgorithm);
        profileParams.setTspServer("http://tsa.belgium.be/connect");
        profileParams.setSigningType(signType);
        profileParams.setSignatureForm(signatureForm);

        dao.save(profileParams);
    }

    protected static void saveProfileTimestampParameters(ProfileTimestampParametersDao dao,
                                                       String profileId,
                                                       DigestAlgorithm digestAlgorithm,
                                                       String canonicalizationMethod,
                                                       TimestampContainerForm containerForm) {
        ProfileTimestampParameters profileParams = new ProfileTimestampParameters();
        profileParams.setProfileId(profileId);
        profileParams.setDigestAlgorithm(digestAlgorithm);
        profileParams.setCanonicalizationMethod(canonicalizationMethod);
        profileParams.setContainerForm(containerForm);
        profileParams.setTspServer("http://tsa.belgium.be/connect");

        dao.save(profileParams);
    }

}
