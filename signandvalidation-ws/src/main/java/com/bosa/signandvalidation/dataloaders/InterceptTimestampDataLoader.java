package com.bosa.signandvalidation.dataloaders;

import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;

public class InterceptTimestampDataLoader extends TimestampDataLoader {

    @Override
    public byte[] get(String url) {
        try {
            return super.get(url);
        } catch(Exception e) {
            DataLoadersExceptionLogger.logExceptionForThread(e, DataLoadersExceptionLogger.Types.TIMESTAMP);
            throw e;
        }
    }

    @Override
    public byte[] post(String url, byte[] content) {
        try {
            return super.post(url, content);
        } catch(Exception e) {
            DataLoadersExceptionLogger.logExceptionForThread(e, DataLoadersExceptionLogger.Types.TIMESTAMP);
            throw e;
        }
    }
}
