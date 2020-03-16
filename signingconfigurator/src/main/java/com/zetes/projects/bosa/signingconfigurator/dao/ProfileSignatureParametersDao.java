package com.zetes.projects.bosa.signingconfigurator.dao;

import com.zetes.projects.bosa.signingconfigurator.model.ProfileSignatureParameters;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ProfileSignatureParametersDao extends JpaRepository<ProfileSignatureParameters, String> {

}
