package com.zetes.projects.bosa.signandvalidation.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zetes.projects.bosa.signandvalidation.SignAndValidationTestBase;
import com.zetes.projects.bosa.signandvalidation.config.ErrorStrings;
import com.zetes.projects.bosa.signandvalidation.model.DataToSignDTO;
import com.zetes.projects.bosa.signandvalidation.model.GetDataToSignForTokenDTO;
import com.zetes.projects.bosa.signandvalidation.model.GetTokenForDocumentDTO;
import com.zetes.projects.bosa.signandvalidation.model.SignDocumentForTokenDTO;
import com.zetes.projects.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import com.zetes.projects.bosa.signingconfigurator.dao.ProfileTimestampParametersDao;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileTimestampParameters;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA256;
import static eu.europa.esig.dss.enumerations.TimestampContainerForm.PDF;
import static javax.xml.crypto.dsig.Transform.ENVELOPED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class SigningControllerBaseTest extends SignAndValidationTestBase implements ErrorStrings {

    @BeforeAll
    public static void fillDB(ApplicationContext applicationContext) {
        ProfileSignatureParametersDao profileSigParamDao = applicationContext.getBean(ProfileSignatureParametersDao.class);
        profileSigParamDao.deleteAll();
        saveProfileSignatureParameters(profileSigParamDao, "XADES_B", null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPED, null, SHA256, null);
        saveProfileSignatureParameters(profileSigParamDao, "XADES_T", null, SignatureLevel.XAdES_BASELINE_T,
                SignaturePackaging.ENVELOPED, null, SHA256, null);
        saveProfileSignatureParameters(profileSigParamDao, "CADES_B", ASiCContainerType.ASiC_S, SignatureLevel.CAdES_BASELINE_B,
                SignaturePackaging.DETACHED, null, SHA256, null);
        saveProfileSignatureParameters(profileSigParamDao, "PADES_B", null, SignatureLevel.PAdES_BASELINE_B,
                SignaturePackaging.ENVELOPED, null, SHA256, null);

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
        return clientSignatureParameters;
    }

    protected static void saveProfileSignatureParameters(ProfileSignatureParametersDao dao,
                                                       String profileId,
                                                       ASiCContainerType containerType,
                                                       SignatureLevel signatureLevel,
                                                       SignaturePackaging signaturePackaging,
                                                       DigestAlgorithm referenceDigestAlgorithm,
                                                       DigestAlgorithm digestAlgorithm,
                                                       MaskGenerationFunction maskGenerationFunction) {
        ProfileSignatureParameters profileParams = new ProfileSignatureParameters();
        profileParams.setProfileId(profileId);
        profileParams.setAsicContainerType(containerType);
        profileParams.setSignatureLevel(signatureLevel);
        profileParams.setSignaturePackaging(signaturePackaging);
        profileParams.setDigestAlgorithm(digestAlgorithm);
        profileParams.setMaskGenerationFunction(maskGenerationFunction);
        profileParams.setReferenceDigestAlgorithm(referenceDigestAlgorithm);
        profileParams.setTspServer("http://tsa.belgium.be/connect");

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
