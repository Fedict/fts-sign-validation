package com.zetes.projects.bosa.signandvalidation.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;
import java.util.List;

@Setter
@Getter
@NoArgsConstructor
public class FileInfoForTokenDTO {
    private List<String> nnAllowedToSign;
    private List<XmlSignInput> inputs;
}
