package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.StorageService;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.web.server.ResponseStatusException;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import static com.bosa.signandvalidation.model.GetFileType.OUT;
import static com.bosa.signandvalidation.model.SigningType.Standard;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;

@SpringBootTest
public class SigningControllerBulkSignTest {

    private static final String IN_FILE0 = "inFile.pdf";
    private static final String IN_FILE1 = "inFile1.pdf";
    private static final String THE_BUCKET = "BUCKET";
    private static final String THE_PREFIX = "PR_";
    private static final String OUT_FILE_0 = "OUT FILE 0";
    private static final String OUT_FILE_1 = "OUT FILE 1";
    @MockBean
    private StorageService storageService;

    @Autowired
    private SigningController sc;

    @Test
    public void testGetFileFromToken() throws Exception {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ServletOutputStream outStream = new ServletOutputStream() {
            public void write(int b) throws IOException { out.write(b); }
            public boolean isReady() { return true; }
            public void setWriteListener(WriteListener listener) { }
        };

        HttpServletResponse resp = mock(HttpServletResponse.class);
        Mockito.when(resp.getOutputStream()).thenReturn(outStream);

        TokenObject token = new TokenObject();
        token.setTokenTimeout(100000);
        token.setSigningType(Standard);
        token.setBucket(THE_BUCKET);
        token.setOutPathPrefix(THE_PREFIX);
        List<TokenSignInput> inputs = new ArrayList<>();
        token.setInputs(inputs);
        TokenSignInput input0 = new TokenSignInput();
        input0.setFilePath(IN_FILE0);
        inputs.add(input0);
        TokenSignInput input1 = new TokenSignInput();
        input1.setFilePath(IN_FILE1);
        inputs.add(input1);
        String tokenStr = sc.saveToken(token);

        // Test security check
        try {
            sc.getFileForToken(tokenStr, OUT, new Integer[]{ 0 }, null, resp);
        } catch (ResponseStatusException e) {
            assertTrue(e.getReason().endsWith("BLOCKED_DOWNLOAD||Forging request attempt !"));
        }

        // Test one file output
        token.setOutDownload(true);
        tokenStr = sc.saveToken(token);
        Mockito.when(storageService.getFileInfo(eq(THE_BUCKET),eq(THE_PREFIX + IN_FILE0))).thenReturn(new FileStoreInfo(MediaType.APPLICATION_PDF, "H", OUT_FILE_0.length()));
        Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(THE_PREFIX + IN_FILE0))).thenReturn(new ByteArrayInputStream(OUT_FILE_0.getBytes()));

        Mockito.when(storageService.getFileInfo(eq(THE_BUCKET),eq(THE_PREFIX + IN_FILE1))).thenReturn(new FileStoreInfo(MediaType.APPLICATION_PDF, "H", OUT_FILE_1.length()));
        Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(THE_PREFIX + IN_FILE1))).thenReturn(new ByteArrayInputStream(OUT_FILE_1.getBytes()));

        sc.getFileForToken(tokenStr, OUT, new Integer[]{ 0 }, null, resp);

        assertEquals(OUT_FILE_0, new String(out.toByteArray()));

        // Test two files output -> zip file
        out.reset();
        sc.getFileForToken(tokenStr, OUT, new Integer[]{ 0, 1 }, null, resp);
        String outStr = new String(out.toByteArray());
        assertEquals("PK", outStr.substring(0, 2));
        assertTrue(outStr.indexOf(THE_PREFIX + IN_FILE0) != -1);
        assertTrue(outStr.indexOf(THE_PREFIX + IN_FILE1) != -1);
    }
}
