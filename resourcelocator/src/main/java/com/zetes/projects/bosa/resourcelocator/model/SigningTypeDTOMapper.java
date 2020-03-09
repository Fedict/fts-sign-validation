package com.zetes.projects.bosa.resourcelocator.model;

import java.util.HashSet;

public class SigningTypeDTOMapper {

    public static final SigningTypeDTOMapper MAPPER = new SigningTypeDTOMapper();

    public SigningTypeDTO map(SigningType signingType) {
        return new SigningTypeDTO(
                signingType.getName(),
                signingType.isActive(),
                signingType.getURI(),
                signingType.getMinimumVersion(),
                new HashSet<>(signingType.getCertificateTypes()),
                signingType.getLogo(),
                signingType.getDescription()
        );
    }

    public SigningType map(SigningTypeDTO signingTypeDTO) {
        return new SigningType(
                signingTypeDTO.getName(),
                signingTypeDTO.isActive(),
                signingTypeDTO.getURI(),
                signingTypeDTO.getMinimumVersion(),
                new HashSet<>(signingTypeDTO.getCertificateTypes()),
                signingTypeDTO.getLogo(),
                signingTypeDTO.getDescription()
        );
    }

}
