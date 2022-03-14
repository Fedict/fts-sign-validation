/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

import lombok.Data;
import org.springframework.http.MediaType;

/**
 *
 * @author cmo
 */
@Data
public class FileStoreInfo {
    private final MediaType contentType;
    private final String hash;
    private final long size;

    public FileStoreInfo(MediaType contentType, String hash, long size) {
        this.contentType = contentType;
        this.size = size;
        this.hash = hash;
    }
}
