package com.zetes.projects.bosa.signandvalidation.model;

import eu.europa.esig.dss.model.MimeType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SignElement {
    private String id;
    private MimeType type;
}
