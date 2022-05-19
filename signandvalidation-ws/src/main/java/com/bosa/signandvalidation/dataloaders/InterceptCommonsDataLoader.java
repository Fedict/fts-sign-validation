
package com.bosa.signandvalidation.dataloaders;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;

public class InterceptCommonsDataLoader extends CommonsDataLoader {

    private DataLoadersExceptionLogger.Types type;

    public InterceptCommonsDataLoader(DataLoadersExceptionLogger.Types type) {
        this.type = type;
    }

    @Override
    public byte[] get(String url) {
        try {
            return super.get(url);
        } catch(Exception e) {
            DataLoadersExceptionLogger.logExceptionForThread(e, type);
            throw e;
        }
    }

    @Override
    public byte[] get(String url, boolean refresh) {
        try {
            return super.get(url, refresh);
        } catch(Exception e) {
            DataLoadersExceptionLogger.logExceptionForThread(e, type);
            throw e;
        }
    }

    @Override
    public byte[] post(String url, byte[] content) {
        try {
            return super.post(url, content);
        } catch(Exception e) {
            DataLoadersExceptionLogger.logExceptionForThread(e, type);
            throw e;
        }
    }
}
