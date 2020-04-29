package com.zetes.projects.bosa.signingconfigurator.dao;

import com.zetes.projects.bosa.signingconfigurator.model.ProfileSignatureParameters;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ProfileSignatureParametersDao extends JpaRepository<ProfileSignatureParameters, String> {

    @Query("SELECT params FROM ProfileSignatureParameters params WHERE params.isDefault = true")
    Optional<ProfileSignatureParameters> findDefault();

}
