package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.SignatureIndicationsDTO;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.simplereport.jaxb.*;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static com.bosa.signandvalidation.config.ErrorStrings.CERT_REVOKED;
import static eu.europa.esig.dss.enumerations.Indication.*;
import static eu.europa.esig.dss.enumerations.SubIndication.HASH_FAILURE;
import static eu.europa.esig.dss.enumerations.SubIndication.SIGNED_DATA_NOT_FOUND;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class JadesServiceTest {

    @Test
    public void signAndVerify() throws Exception {
    }
}
