package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class GetDataToSignXMLElementsDTO {
    private String signingProfileId;
    private RemoteDocument toSignDocument;
    private ClientSignatureParameters clientSignatureParameters;
    private PolicyDTO policy;
    private List<String> elementIdsToSign;
}
