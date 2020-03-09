package com.zetes.projects.bosa.resourcelocator.service;

import com.zetes.projects.bosa.resourcelocator.dao.SigningTypeDAO;
import com.zetes.projects.bosa.resourcelocator.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class LocatorService {

    private static final Logger LOG = LoggerFactory.getLogger(LocatorService.class);

    @Autowired
    private SigningTypeDAO signingTypeDAO;

    public SigningTypeDTO getSigningTypeByName(String name) {
        LOG.info(("Getting signing type by name..."));
        return signingTypeDAO.findById(name)
                .filter(SigningType::isActive)
                .map(SigningTypeDTOMapper.MAPPER::map)
                .orElse(null);
    }

    public SigningTypeListDTO getSigningTypesByCertificateType(CertificateType certificateType) {
        LOG.info(("Getting signing types by certificate type..."));
        List<SigningTypeDTO> signingTypes = signingTypeDAO.findByCertificateType(certificateType).stream()
                .filter(SigningType::isActive)
                .map(SigningTypeDTOMapper.MAPPER::map)
                .collect(Collectors.toList());

        return new SigningTypeListDTO(signingTypes);
    }

}
