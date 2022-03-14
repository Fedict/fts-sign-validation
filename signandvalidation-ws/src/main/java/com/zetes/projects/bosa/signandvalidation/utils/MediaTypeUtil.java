/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.utils;

import org.springframework.http.MediaType;

import static org.springframework.http.MediaType.*;

/**
 * Class to manage mimetypes in a backward compatible way to the existing code...
 * Issue is "application/xslt+xml" not available in MediaType
 *
 * @author cmo
 */
public class MediaTypeUtil {

    public static final String APPLICATION_XSLT_XML_VALUE = "application/xslt+xml";

    public static final MediaType APPLICATION_XSLT_XML = new MediaType("application", "xslt+xml");

    public static boolean isXMLFilename(String filename) {
        return "xml".equals(getExtFromFilename(filename));
    }

    public static MediaType getMediaTypeFromFilename(String fileName) {
        String ext = getExtFromFilename(fileName);
        if ("pdf".equals(ext)) return APPLICATION_PDF;
        if ("xml".equals(ext)) return APPLICATION_XML;
        if ("xslt".equals(ext)) return APPLICATION_XSLT_XML;
        if ("txt".equals(ext)) return TEXT_PLAIN;
        return APPLICATION_OCTET_STREAM;
    }

    private static String getExtFromFilename(String fileName) {
        int pos = fileName.lastIndexOf('.');
        if (pos != -1) return fileName.substring(pos + 1).toLowerCase();
        return null;
    }

}
