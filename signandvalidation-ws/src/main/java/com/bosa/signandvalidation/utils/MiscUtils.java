package com.bosa.signandvalidation.utils;

import com.bosa.signandvalidation.controller.SigningController;
import com.bosa.signandvalidation.service.BosaRemoteDocumentValidationService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

public class MiscUtils
{
    private static final Logger logger = Logger.getLogger(MiscUtils.class.getName());

    public static RemoteDocument getPolicyFile(String fileName) throws IOException {
        logger.warning("Loading policy for signature validation : " + fileName);
        InputStream genericIs = BosaRemoteDocumentValidationService.class.getResourceAsStream("/policy/" + fileName);
        if (genericIs == null) throw new IOException("Policy file not found");
        RemoteDocument policyDocument = new RemoteDocument(Utils.toByteArray(genericIs), fileName);
        genericIs.close();
        return policyDocument;
    }
}
