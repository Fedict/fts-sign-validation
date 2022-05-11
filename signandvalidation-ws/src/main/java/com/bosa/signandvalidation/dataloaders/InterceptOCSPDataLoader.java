package com.bosa.signandvalidation.dataloaders;

import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;

public class InterceptOCSPDataLoader extends OCSPDataLoader {

    @Override
    public byte[] get(String url) {
        try {
            return super.get(url);
        } catch(Exception e) {
            DataLoadersExceptionLogger.addException(e, DataLoadersExceptionLogger.Types.OCSP);
            throw e;
        }
    }

    @Override
    public byte[] get(String url, boolean refresh) {
        try {
            return super.get(url, refresh);
        } catch(Exception e) {
            DataLoadersExceptionLogger.addException(e, DataLoadersExceptionLogger.Types.OCSP);
            throw e;
        }
    }

    @Override
    public byte[] post(String url, byte[] content) {
        try {
            return super.post(url.replaceFirst("http://", "http://ww"), content);
        } catch(Exception e) {
            DataLoadersExceptionLogger.addException(e, DataLoadersExceptionLogger.Types.OCSP);
            throw e;
        }
    }
}
