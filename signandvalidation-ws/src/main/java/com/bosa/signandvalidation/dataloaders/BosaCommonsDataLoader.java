
package com.bosa.signandvalidation.dataloaders;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;

public class BosaCommonsDataLoader extends CommonsDataLoader {

    private BosaDataLoaders.Types type;

    public BosaCommonsDataLoader(BosaDataLoaders.Types type) {
        this.type = type;
    }

    @Override
    public byte[] get(String url) {
        try {
            return super.get(url);
        } catch(Exception e) {
            BosaDataLoaders.setException(e, type);
            throw e;
        }
    }

    @Override
    public byte[] get(String url, boolean refresh) {
        try {
            return super.get(url, refresh);
        } catch(Exception e) {
            BosaDataLoaders.setException(e, type);
            throw e;
        }
    }

    @Override
    public byte[] post(String url, byte[] content) {
        try {
            return super.post(url + "x", content);
        } catch(Exception e) {
            BosaDataLoaders.setException(e, type);
            throw e;
        }
    }
}
