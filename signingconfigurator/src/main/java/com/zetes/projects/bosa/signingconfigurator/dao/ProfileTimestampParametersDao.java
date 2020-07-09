package com.zetes.projects.bosa.signingconfigurator.dao;

import com.zetes.projects.bosa.signingconfigurator.model.ProfileTimestampParameters;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ProfileTimestampParametersDao extends JpaRepository<ProfileTimestampParameters, String> {

    @Query("SELECT params FROM ProfileTimestampParameters params WHERE params.isDefault = true")
    Optional<ProfileTimestampParameters> findDefault();

}
