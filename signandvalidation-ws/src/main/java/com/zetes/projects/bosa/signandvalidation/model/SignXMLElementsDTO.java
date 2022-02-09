package com.zetes.projects.bosa.signandvalidation.model;

import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.PolicyParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignXMLElementsDTO {
    private String signingProfileId;
    private RemoteDocument toSignDocument;
    private ClientSignatureParameters clientSignatureParameters;
    private PolicyParameters policy;
    private List<SignElement> elementsToSign;

    private byte signatureValue[];
}
