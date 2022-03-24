/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signingconfigurator.dao;

import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author wouter
 */
public class ProfileSignatureParametersDaoTest {
    
    public ProfileSignatureParametersDaoTest() {
    }
    
    @BeforeAll
    public static void setUpClass() {
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    @BeforeEach
    public void setUp() {
    }
    
    @AfterEach
    public void tearDown() {
    }

    /**
     * Test of findById method, of class ProfileSignatureParametersDao.
     */
    @Test
    public void testFindById() throws Exception {
        System.out.println("findById");
        String id = "test";
        ProfileSignatureParametersDao instance = new ProfileSignatureParametersDao();
        ProfileSignatureParameters expResult = new ProfileSignatureParameters();
        expResult.setProfileId(id);
        instance.save(expResult);
        ProfileSignatureParameters result = instance.findById(id);
        assertEquals(expResult, result);
    }

    /**
     * Test of findDefault method, of class ProfileSignatureParametersDao.
     */
    @Test
    public void testFindDefault() throws Exception {
        System.out.println("findDefault");
        ProfileSignatureParametersDao instance = new ProfileSignatureParametersDao();
        ProfileSignatureParameters expResult = new ProfileSignatureParameters();
        expResult.setIsDefault(true);
        instance.save(expResult);
        ProfileSignatureParameters result = instance.findDefault();
        assertEquals(expResult, result);
    }

    /**
     * Test of deleteAll method, of class ProfileSignatureParametersDao.
     */
    @Test
    public void testDeleteAll() {
        System.out.println("deleteAll");
        ProfileSignatureParametersDao instance = new ProfileSignatureParametersDao();
        instance.deleteAll();
    }

    /**
     * Test of save method, of class ProfileSignatureParametersDao.
     */
    @Test
    public void testSave() {
        System.out.println("save");
        ProfileSignatureParameters p = new ProfileSignatureParameters();
        ProfileSignatureParametersDao instance = new ProfileSignatureParametersDao();
        instance.save(p);
    }
}
