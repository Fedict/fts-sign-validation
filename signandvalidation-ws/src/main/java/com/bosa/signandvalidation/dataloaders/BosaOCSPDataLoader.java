package com.bosa.signandvalidation.dataloaders;

import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;

public class BosaOCSPDataLoader extends OCSPDataLoader {

    @Override
    public byte[] get(String url) {
        try {
            return super.get(url);
        } catch(Exception e) {
            BosaDataLoaders.setException(e, BosaDataLoaders.Types.OCSP);
            throw e;
        }
    }

    @Override
    public byte[] get(String url, boolean refresh) {
        try {
            return super.get(url, refresh);
        } catch(Exception e) {
            BosaDataLoaders.setException(e, BosaDataLoaders.Types.OCSP);
            throw e;
        }
    }

    @Override
    public byte[] post(String url, byte[] content) {
        try {
            return super.post(url.replaceFirst("ocsp.eidpki.belgium.be", "toto"), content);
        } catch(Exception e) {
            BosaDataLoaders.setException(e, BosaDataLoaders.Types.OCSP);
            throw e;
        }
    }
}
