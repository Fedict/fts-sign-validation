package com.zetes.projects.bosa.resourcelocator.dao;

import com.zetes.projects.bosa.resourcelocator.model.CertificateType;
import com.zetes.projects.bosa.resourcelocator.model.SigningType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SigningTypeDAO extends JpaRepository<SigningType, String> {

    @Query("SELECT s" +
            " FROM SigningType s" +
            " JOIN s.certificateTypes c" +
            " WHERE c = :certificateType")
    List<SigningType> findByCertificateType(@Param("certificateType") CertificateType certificateType);

}
