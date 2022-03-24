package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.model.FrontEndErrorReqDTO;
import com.zetes.projects.bosa.signandvalidation.model.FrontEndErrorRespDTO;
import com.zetes.projects.bosa.signandvalidation.SignAndValidationTestBase;

import org.springframework.beans.factory.annotation.Autowired;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class LoggingControllerTest extends SignAndValidationTestBase {

    @Autowired
    ObjectMapper mapper;

    public static final String LOGGINGERROR_ENDPOINT = "/logging/error";

    @Test
    public void testLogging() {
        FrontEndErrorReqDTO errReq = new FrontEndErrorReqDTO("FE_NATIVE_ERR", "blah blah", "12345678", "hregO7hw");

        FrontEndErrorRespDTO resp = this.restTemplate.postForObject(LOCALHOST + port + LOGGINGERROR_ENDPOINT, errReq, FrontEndErrorRespDTO.class);
        assertNotNull(resp);
        assertNotNull(resp.getRef());
    }
}
