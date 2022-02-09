/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

import lombok.Data;

/**
 *
 * @author cmo
 */
@Data
public class FileStoreInfo {
    private final String contentType;
    private final String hash;

    public FileStoreInfo(String contentType, String hash) {
        this.contentType = contentType;
        this.hash = hash;
    }
}
