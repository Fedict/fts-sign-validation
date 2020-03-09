package com.zetes.projects.bosa.resourcelocator.model;

import javax.persistence.*;
import java.util.Set;

@Entity
@Table
public class SigningType {

    @Id
    private String name;

    @Column
    private Boolean active;

    @Column
    private String URI;

    @Column
    private String minimumVersion;

    @ElementCollection(targetClass = CertificateType.class, fetch = FetchType.EAGER)
    private Set<CertificateType> certificateTypes;

    @Lob
    private byte[] logo;

    @Column
    private String description;

    public SigningType() {
    }

    public SigningType(String name, Boolean active, String URI, String minimumVersion, Set<CertificateType> certificateTypes, byte[] logo, String description) {
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
