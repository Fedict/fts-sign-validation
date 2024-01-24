package com.bosa.signandvalidation.model;

import com.bosa.signandvalidation.service.CertInfo;
import com.bosa.signandvalidation.model.SignatureLevel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

// Check for changes in DSS Enum values
public class SignatureLevelTest {
    @Test
    public void testDSSValueChanges() {
        eu.europa.esig.dss.enumerations.SignatureLevel[] values = eu.europa.esig.dss.enumerations.SignatureLevel.values();
        assertEquals(values.length, SignatureLevel.values().length);

        for (eu.europa.esig.dss.enumerations.SignatureLevel lev : values) {
            assertNotNull(SignatureLevel.valueOf(lev.name()));
        }
    }
}
