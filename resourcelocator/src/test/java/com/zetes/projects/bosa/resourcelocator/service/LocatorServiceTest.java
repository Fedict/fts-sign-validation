package com.zetes.projects.bosa.resourcelocator.service;

import com.zetes.projects.bosa.resourcelocator.dao.SigningTypeDAO;
import com.zetes.projects.bosa.resourcelocator.model.CertificateType;
import com.zetes.projects.bosa.resourcelocator.model.SigningType;
import com.zetes.projects.bosa.resourcelocator.model.SigningTypeDTO;
import com.zetes.projects.bosa.resourcelocator.model.SigningTypeListDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Arrays;
import java.util.HashSet;

import static com.zetes.projects.bosa.resourcelocator.model.CertificateType.AUTHORISATION;
import static com.zetes.projects.bosa.resourcelocator.model.CertificateType.NON_REPUDIATION;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class LocatorServiceTest {

    @Autowired
    private SigningTypeDAO signingTypeDAO;

    @Autowired
    private LocatorService locatorService;

    @BeforeEach
    public void clearDB() {
        signingTypeDAO.deleteAll();
    }

    @Test
    public void contextLoads() {
    }

    @Test
    public void byNameNotFound() {
        // when
        SigningTypeDTO result = locatorService.getSigningTypeByName("eid");

        // then
        assertNull(result);
    }

    @Test
    public void byNameFoundInactive() {
        // given
        saveSigningType("eid", false);

        // when
        SigningTypeDTO result = locatorService.getSigningTypeByName("eid");

        // then
        assertNull(result);
    }

    @Test
    public void byNameFoundActive() {
        // given
        saveSigningType("eid", true);

        // when
        SigningTypeDTO result = locatorService.getSigningTypeByName("eid");

        // then
        assertNotNull(result);
        assertEquals("eid", result.getName());
    }

    @Test
    public void byCertificateTypeNotFound() {
        // when
        SigningTypeListDTO result = locatorService.getSigningTypesByCertificateType(AUTHORISATION);

        // then
        assertNotNull(result.getSigningTypes());
        assertEquals(0, result.getSigningTypes().size());
    }

    @Test
    public void byCertificateFoundInactive() {
        // given
        saveSigningType("eid", false, AUTHORISATION);

        // when
        SigningTypeListDTO result = locatorService.getSigningTypesByCertificateType(AUTHORISATION);

        // then
        assertNotNull(result.getSigningTypes());
        assertEquals(0, result.getSigningTypes().size());
    }

    @Test
    public void byCertificateFoundActive() {
        // given
        saveSigningType("eid", true, AUTHORISATION);

        // when
        SigningTypeListDTO result = locatorService.getSigningTypesByCertificateType(AUTHORISATION);

        // then
        assertNotNull(result.getSigningTypes());
        assertEquals(1, result.getSigningTypes().size());
        assertEquals("eid", result.getSigningTypes().get(0).getName());
    }

    @Test
    public void byCertificateFoundMultipleActive() {
        // given
        saveSigningType("one", true, AUTHORISATION);
        saveSigningType("two", true, AUTHORISATION, NON_REPUDIATION);
        saveSigningType("three", true, NON_REPUDIATION);

        // when
        SigningTypeListDTO result = locatorService.getSigningTypesByCertificateType(AUTHORISATION);

        // then
        assertNotNull(result.getSigningTypes());
        assertEquals(2, result.getSigningTypes().size());
        assertEquals("one", result.getSigningTypes().get(0).getName());
        assertEquals("two", result.getSigningTypes().get(1).getName());
    }

    private void saveSigningType(String name, Boolean active, CertificateType... certificateTypes) {
        SigningType signingType = new SigningType();
        signingType.setName(name);
        signingType.setActive(active);
        signingType.setCertificateTypes(new HashSet<>(Arrays.asList(certificateTypes)));

        signingTypeDAO.save(signingType);
    }

}
