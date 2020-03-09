package com.zetes.projects.bosa.resourcelocator.model;

import java.util.Set;

public class SigningTypeDTO {

    private String name;

    private Boolean active;

    private String URI;

    private String minimumVersion;

    private Set<CertificateType> certificateTypes;

    private byte[] logo;

    private String description;

    public SigningTypeDTO() {
    }

    public SigningTypeDTO(String name, Boolean active, String URI, String minimumVersion, Set<CertificateType> certificateTypes, byte[] logo, String description) {
        this.name = name;
        this.active = active;
        this.URI = URI;
        this.minimumVersion = minimumVersion;
        this.certificateTypes = certificateTypes;
        this.logo = logo;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Boolean isActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public String getURI() {
        return URI;
    }

    public void setURI(String URI) {
        this.URI = URI;
    }

    public String getMinimumVersion() {
        return minimumVersion;
    }

    public void setMinimumVersion(String minimumVersion) {
        this.minimumVersion = minimumVersion;
    }

    public Set<CertificateType> getCertificateTypes() {
        return certificateTypes;
    }

    public void setCertificateTypes(Set<CertificateType> certificateTypes) {
        this.certificateTypes = certificateTypes;
    }

    public byte[] getLogo() {
        return logo;
    }

    public void setLogo(byte[] logo) {
        this.logo = logo;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

}
