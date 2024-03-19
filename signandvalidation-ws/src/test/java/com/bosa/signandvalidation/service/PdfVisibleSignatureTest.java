package com.bosa.signandvalidation.service;

import com.bosa.signingconfigurator.exception.NullParameterException;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureFieldParameters;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class PdfVisibleSignatureTest {
    @Test
    public void testFillCoordinates() throws Exception {
        RemoteSignatureFieldParameters sigFieldParams = new RemoteSignatureFieldParameters();
        PdfVisibleSignatureService.convertFieldCoords("1,2,3,4,5", null, sigFieldParams);
        assertEquals(1, sigFieldParams.getPage());
        assertEquals((float) 2.0, sigFieldParams.getOriginX());
        assertEquals((float) 3.0, sigFieldParams.getOriginY());
        assertEquals((float) 4.0, sigFieldParams.getWidth());
        assertEquals((float) 5.0, sigFieldParams.getHeight());
    }

    @Test
    public void testMissingPSP() throws Exception {
        try {
            RemoteSignatureFieldParameters sigFieldParams = new RemoteSignatureFieldParameters();
            PdfVisibleSignatureService.convertFieldCoords("default", null, sigFieldParams);
            fail(); // we shouldn't get here
        } catch (NullParameterException e) {
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void testFillPSPCoordinates() throws Exception {
        RemoteSignatureFieldParameters sigFieldParams = new RemoteSignatureFieldParameters();
        PdfVisibleSignatureService.convertFieldCoords("default", "1,2,3,4,5", sigFieldParams);
        assertEquals(1, sigFieldParams.getPage());
        assertEquals((float) 2.0, sigFieldParams.getOriginX());
        assertEquals((float) 3.0, sigFieldParams.getOriginY());
        assertEquals((float) 4.0, sigFieldParams.getWidth());
        assertEquals((float) 5.0, sigFieldParams.getHeight());
    }

    @Test
    public void testMakeText() throws Exception {
        LinkedHashMap<String,String> texts = new LinkedHashMap<String,String>();
        texts.put("en", "Signed by %gn% %sn% (%nn%=%rrn%)\non %d(MMM d YYYY)%");
        texts.put("nl", "Getekend door %gn% %sn% (%nn%=%rrn%)\nop %d(d MMM YYYY)%");
        texts.put("fr", "Signé par %gn% %sn% (%nn%=%rrn%)\nau %d(d MMM YYYY)%");
        texts.put("de", "Unterzeichnet von %gn% %sn% (%nn%=%rrn%)\nam %d(d MMM YYYY)%");

        Date signingDate = new Date();
        signingDate.setTime(1623318619435L);

        RemoteCertificate signingCert = CertInfoTest.getTomTestCertificate();

        String text = PdfVisibleSignatureService.makeText(null, null, signingDate, signingCert);
        assertEquals("Tom Test", text);
        text = PdfVisibleSignatureService.makeText(texts, null, signingDate, signingCert);
        assertEquals("Signed by Tom Test (73040102749=73040102749)\non Jun 10 2021", text);
        text = PdfVisibleSignatureService.makeText(texts, "en", signingDate, signingCert);
        assertEquals("Signed by Tom Test (73040102749=73040102749)\non Jun 10 2021", text);
        text = PdfVisibleSignatureService.makeText(texts, "nl", signingDate, signingCert);
        // Ignore minor "locale" differences for date formatting (Ideally we should change the locale in the main code but there is a risk of PRD regression)
        text = text.replaceAll(" jun\\. ", " jun ");
        assertEquals("Getekend door Tom Test (73040102749=73040102749)\nop 10 jun 2021", text);
        text = PdfVisibleSignatureService.makeText(texts, "fr", signingDate, signingCert);
        assertEquals("Signé par Tom Test (73040102749=73040102749)\nau 10 juin 2021", text);
        text = PdfVisibleSignatureService.makeText(texts, "de", signingDate, signingCert);
        // Ignore minor "locale" differences for date formatting (Ideally we should change the locale in the main code but there is a risk of PRD regression)
        text = text.replaceAll(" Juni ", " Jun ");
        assertEquals("Unterzeichnet von Tom Test (73040102749=73040102749)\nam 10 Jun 2021", text);
        try {
            PdfVisibleSignatureService.makeText(texts, "xx", signingDate, signingCert);
            fail(); // we shouldn't get here
        } catch (NullParameterException e) {
            System.out.println(e.getMessage());
        }

        texts = new LinkedHashMap<String,String>();
        texts.put("en", "%d(MMM d YYYY)% %d(yyyy.MMMMM.dd)%");
        text = PdfVisibleSignatureService.makeText(texts, null, signingDate, signingCert);
        assertEquals("Jun 10 2021 2021.June.10", text);
   }
}
