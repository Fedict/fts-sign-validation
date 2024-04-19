package com.bosa.signandvalidation.config;

import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;

import java.util.List;

/**********************************************************************************
 * The URNByPassDataloader is there to allow 'policySpuri' with "urn:" as
 * protocol. The dataloader will return the 'policySpuri' value as the content of the Policy.
 * IT will also not try to fetch the URL content.
 * Therefore the policyDigestValue must be calculated on the value of 'policySpuri'
 * This is because Fednot is depending on "urn:" policySpuri.
 ***********************************************************************************/

public class URNByPassDataloader implements DataLoader {
    private final FileCacheDataLoader dataLoader;

    public URNByPassDataloader(FileCacheDataLoader dataLoader) {
        this.dataLoader = dataLoader;
    }

    @Override
    public byte[] get(String urlString) {
        if (urlString.startsWith("urn:")) return urlString.getBytes();
        return dataLoader.get(urlString);
    }

    @Override
    public DataAndUrl get(List<String> urlStrings) {
        for(String urlString : urlStrings) {
            byte[] bytes = this.get(urlString);
            if (bytes != null) return new DataLoader.DataAndUrl(urlString, bytes);
        }
        return dataLoader.get(urlStrings);
    }

    @Override
    public byte[] post(String urlString, byte[] bytesToPost) {
        return dataLoader.post(urlString, bytesToPost);
    }

    @Override
    public void setContentType(String contentType) {
        dataLoader.setContentType(contentType);
    }
}
