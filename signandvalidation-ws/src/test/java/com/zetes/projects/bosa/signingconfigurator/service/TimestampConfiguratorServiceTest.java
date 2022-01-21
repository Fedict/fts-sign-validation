package com.zetes.projects.bosa.signingconfigurator.service;

import com.zetes.projects.bosa.signingconfigurator.dao.ProfileTimestampParametersDao;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileTimestampParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampContainerForm;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import static eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA256;
import static eu.europa.esig.dss.enumerations.TimestampContainerForm.PDF;
import static javax.xml.crypto.dsig.CanonicalizationMethod.ENVELOPED;
import static javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Import(FileCacheDataLoader.class)
@ActiveProfiles("localh2")
public class TimestampConfiguratorServiceTest {

    @MockBean
    private OnlineTSPSource tspSource;

    @Autowired
    private ProfileTimestampParametersDao dao;

    @Autowired
    private SigningConfiguratorService service;

    @BeforeEach
    public void clearDB() {
        dao.deleteAll();
    }

    @Test
    public void contextLoads() {
    }

    @Test
    public void throwsProfileNotFoundException() {
        ProfileNotFoundException exception = assertThrows(

                ProfileNotFoundException.class,
                () -> service.getTimestampParams("NOTFOUND")
        );

        assertEquals("NOTFOUND not found", exception.getMessage());
    }

    @Test
    public void throwsDefaultProfileNotFoundException() {
        ProfileNotFoundException exception = assertThrows(
                ProfileNotFoundException.class,
                () -> service.getTimestampParams(null)
        );

        assertEquals("Default profile not found", exception.getMessage());
    }

    @Test
    public void retrievesProfileParametersCorrectly() throws Exception {
        // given
        saveProfileTimestampParameters("PROFILE_1", null, SHA256, ENVELOPED, PDF, "tspServer");

        // when
        RemoteTimestampParameters result = service.getTimestampParams("PROFILE_1");

        // then
        assertEquals(SHA256, result.getDigestAlgorithm());
        assertEquals(ENVELOPED, result.getCanonicalizationMethod());
        assertEquals(PDF, result.getTimestampContainerForm());
    }

    @Test
    public void retrievesDefaultParametersCorrectly() throws Exception {
        // given
        saveProfileTimestampParameters("PROFILE_1", true, SHA256, ENVELOPED, PDF, "tspServer");

        // when
        RemoteTimestampParameters result = service.getTimestampParams(null);

        // then
        assertEquals(SHA256, result.getDigestAlgorithm());
        assertEquals(ENVELOPED, result.getCanonicalizationMethod());
        assertEquals(PDF, result.getTimestampContainerForm());
    }

    @Test
    public void overridesNullParametersCorrectly() throws Exception {
        // given
        saveProfileTimestampParameters("PROFILE_1", null, null, null, null, "tspServer");

        // when
        RemoteTimestampParameters result = service.getTimestampParams("PROFILE_1");

        // then
        assertEquals(SHA256, result.getDigestAlgorithm());
        assertEquals(EXCLUSIVE, result.getCanonicalizationMethod());
        assertNull(result.getTimestampContainerForm());
    }

    private void saveProfileTimestampParameters(String profileId,
                                                Boolean isDefault,
                                                DigestAlgorithm digestAlgorithm,
                                                String canonicalizationMethod,
                                                TimestampContainerForm containerForm,
                                                String tspServer) {
        ProfileTimestampParameters profileParams = new ProfileTimestampParameters();
        profileParams.setProfileId(profileId);
        profileParams.setIsDefault(isDefault);
        profileParams.setDigestAlgorithm(digestAlgorithm);
        profileParams.setCanonicalizationMethod(canonicalizationMethod);
        profileParams.setContainerForm(containerForm);

        profileParams.setTspServer(tspServer);

        dao.save(profileParams);
    }
}
