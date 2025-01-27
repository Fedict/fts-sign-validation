package com.bosa.signandvalidation.controller;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

public class SigningControllerValidationTest {

    @Test
    public void testInvalidPsfC() throws Exception {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SigningController.checkPsfC(null, "Invalid");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature coordinates:"));
    }

    @Test
    public void testInvalidPsfC1() throws Exception {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SigningController.checkPsfC(null, "1,2,3,4,A");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature coordinates:"));
    }

    @Test
    public void testInvalidPsfC2() throws Exception {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SigningController.checkPsfC(null, "1,2,3,400,");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature coordinates:"));
    }

    @Test
    public void testInvalidPsfC3() throws Exception {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SigningController.checkPsfC(null, "13,20,3");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature coordinates:"));
    }

    @Test
    public void testInvalidPsfC4() throws Exception {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SigningController.checkPsfC(null, "1,2,30,4,5,6");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature coordinates:"));
    }

    @Test
    public void testInvalidPageAndBoundaries() throws Exception {

        PDDocument pdfDoc = Loader.loadPDF(new File("src/test/resources/sample.pdf"));
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SigningController.checkPsfC(pdfDoc, "20,1,1,2,2");
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||Invalid PDF signature page"));

        exception = assertThrows(ResponseStatusException.class, () -> {
            SigningController.checkPsfC(pdfDoc, "1,100000,1,2,2");
        });
        assertTrue(exception.getMessage().contains("SIGNATURE_OUT_OF_BOUNDS||The new signature field position is outside the page dimensions:"));

        exception = assertThrows(ResponseStatusException.class, () -> {
            SigningController.checkPsfC(pdfDoc, "1,100,100,20000,20000");
        });
        assertTrue(exception.getMessage().contains("SIGNATURE_OUT_OF_BOUNDS||The new signature field position is outside the page dimensions:"));
    }

    @Test
    public void testMissingPsfN() throws Exception {
        PDDocument pdfDoc = Loader.loadPDF(new File("src/test/resources/sample.pdf"));
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SigningController.checkVisibleSignatureParameters(null, "Invalid", null, pdfDoc);
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||The PDF signature field does exist : Invalid"));
    }

    @Test
    public void testPsfNAlreadySigned() throws Exception {
        PDDocument pdfDoc = Loader.loadPDF(new File("src/test/resources/signed_visible_sigfields.pdf"));
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            SigningController.checkVisibleSignatureParameters(null, "signature_1", null, pdfDoc);
        });
        assertTrue(exception.getMessage().contains("INVALID_PARAM||The specified PDF signature field already contains a signature."));
    }

    @Test
    public void testValidPsfN() throws Exception {
        PDDocument pdfDoc = Loader.loadPDF(new File("src/test/resources/visible_sigfields.pdf"));
        PDRectangle dim = SigningController.checkVisibleSignatureParameters(null, "signature_1", null, pdfDoc);

        assertEquals(112, (int)dim.getHeight());
        assertEquals(221, (int)dim.getWidth());
    }
}
