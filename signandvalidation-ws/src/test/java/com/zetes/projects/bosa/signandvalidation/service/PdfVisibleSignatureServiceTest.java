package com.zetes.projects.bosa.signandvalidation.service;

import eu.europa.esig.dss.ws.dto.RemoteColor;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureFieldParameters;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.util.*;

@SpringBootTest
@ActiveProfiles("localh2")
public class PdfVisibleSignatureServiceTest {
    @Test
    public void testFillCoordinates() throws Exception {
        RemoteSignatureFieldParameters sigFieldParams = new RemoteSignatureFieldParameters();
        PdfVisibleSignatureService.fillCoordinates(sigFieldParams, "1,2,3,4,5");
        assertEquals(1, sigFieldParams.getPage());
        assertEquals((float) 2.0, sigFieldParams.getOriginX());
        assertEquals((float) 3.0, sigFieldParams.getOriginY());
        assertEquals((float) 4.0, sigFieldParams.getWidth());
        assertEquals((float) 5.0, sigFieldParams.getHeight());
    }

    @Test
    public void testMakeColor() throws Exception {
        RemoteColor color = PdfVisibleSignatureService.makeColor("#112233");
        assertEquals(0x11, color.getRed());
        assertEquals(0x22, color.getGreen());
        assertEquals(0x33, color.getBlue());
    } 

    @Test
    public void testMakeText() throws Exception {
        RemoteCertificate signingCert = CertInfoTest.getTomTestCertificate();
        String text = PdfVisibleSignatureService.makeText("Signed by:\n%g %s %%%r%%", signingCert);
        assertEquals("Signed by:\nTom Test %73040102749%", text);
   }
}
