package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.AcroformInfo;
import org.apache.pdfbox.Loader;
import com.bosa.signandvalidation.service.SignCommonService;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.io.File;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class SigningControllerValidationTest {

    @Test
    public void testInvalidPsfC() throws Exception {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SignCommonService.checkPsfC(null, "Invalid");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature coordinates:"));
    }

    @Test
    public void testInvalidPsfC1() throws Exception {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SignCommonService.checkPsfC(null, "1,2,3,4,A");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature coordinates:"));
    }

    @Test
    public void testInvalidPsfC2() throws Exception {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SignCommonService.checkPsfC(null, "1,2,3,400,");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature coordinates:"));
    }

    @Test
    public void testInvalidPsfC3() throws Exception {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SignCommonService.checkPsfC(null, "13,20,3");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature coordinates:"));
    }

    @Test
    public void testInvalidPsfC4() throws Exception {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SignCommonService.checkPsfC(null, "1,2,30,4,5,6");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature coordinates:"));
    }

    @Test
    public void testInvalidPageAndBoundaries() throws Exception {

        PDDocument pdfDoc = Loader.loadPDF(new File("src/test/resources/sample.pdf"));
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SignCommonService.checkPsfC(pdfDoc, "20,1,1,2,2");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature page"));

        exception = assertThrows(ResponseStatusException.class, () -> {
            SignCommonService.checkPsfC(pdfDoc, "1,100000,1,2,2");
        });
        assertTrue(exception.getMessage().contains("SIGNATURE_OUT_OF_BOUNDS||The new signature field position is outside the page dimensions:"));

        exception = assertThrows(ResponseStatusException.class, () -> {
            SignCommonService.checkPsfC(pdfDoc, "1,100,100,20000,20000");
        });
        assertTrue(exception.getMessage().contains("SIGNATURE_OUT_OF_BOUNDS||The new signature field position is outside the page dimensions:"));
    }

    @Test
    public void testMissingPsfN() throws Exception {
        PDDocument pdfDoc = Loader.loadPDF(new File("src/test/resources/sample.pdf"));
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SignCommonService.checkVisibleSignatureParameters(null, "Invalid", true, null, pdfDoc);
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||The specified PDF signature field already contains a signature or does not exists : Invalid"));
    }

    @Test
    public void testPsfNAlreadySigned() throws Exception {
        PDDocument pdfDoc = Loader.loadPDF(new File("src/test/resources/signed_visible_sigfields.pdf"));
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SignCommonService.checkVisibleSignatureParameters(null, "signature_1", true,null, pdfDoc);
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||The specified PDF signature field already contains a signature or does not exists : signature_1"));
    }

    @Test
    public void testValidPsfN() throws Exception {
        PDDocument pdfDoc = Loader.loadPDF(new File("src/test/resources/visible_sigfields.pdf"));
        Map<String, AcroformInfo> info = SignCommonService.checkVisibleSignatureParameters(null, "signature_1", true,null, pdfDoc);

        assertEquals(112, (int)info.get("signature_1").getHeight());
        assertEquals(221, (int)info.get("signature_1").getWidth());
    }
}
