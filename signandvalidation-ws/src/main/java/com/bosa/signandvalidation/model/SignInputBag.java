package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.http.MediaType;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignInputBag {
    private String filePath;
    private boolean isPDF;
    private ClientSignatureParameters clientSigParams;
    private RemoteSignatureParameters parameters;
    private ProfileSignatureParameters signProfile;
    private TokenSignInput tokenInputToSign;
    private List<DSSReference> references;
}
