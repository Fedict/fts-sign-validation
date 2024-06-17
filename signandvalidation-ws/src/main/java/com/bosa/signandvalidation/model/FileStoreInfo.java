/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import lombok.Data;
import org.springframework.http.MediaType;

import java.time.LocalDateTime;

/**
 *
 * @author cmo
 */
@Data
public class FileStoreInfo {
    private final MediaType contentType;
    private final String hash;
    private final long size;
    private final LocalDateTime lastModification;
    private final boolean fileExists;

    public FileStoreInfo(MediaType contentType, String hash, long size) {
        this.contentType = contentType;
        this.size = size;
        this.hash = hash;
        this.fileExists = true;
        this.lastModification = LocalDateTime.now();
    }
    public FileStoreInfo() {
        this.contentType = MediaType.TEXT_PLAIN;
        this.size = 0;
        this.hash = "";
        this.fileExists = false;
        this.lastModification = LocalDateTime.now();
    }

    public FileStoreInfo(MediaType contentType, String hash, long size, LocalDateTime lastModification) {
        this.contentType = contentType;
        this.size = size;
        this.hash = hash;
        this.fileExists = true;
        this.lastModification = lastModification;
    }
}