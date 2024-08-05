package com.bosa.signandvalidation.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;

@Getter
@Setter
@XmlAccessorType(XmlAccessType.FIELD)
@NoArgsConstructor
public class XadesFile {
    @XmlAttribute
    private String id;

    @XmlAttribute
    private String name;

    @XmlAttribute
    private Long size;

    private String content;
}
