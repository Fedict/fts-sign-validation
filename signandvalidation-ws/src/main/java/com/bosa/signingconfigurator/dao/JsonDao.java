/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signingconfigurator.dao;

import com.bosa.signingconfigurator.model.JsonObject;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author wouter
 */
public abstract class JsonDao {
    private final String JSON_PATH;
    
    private final Boolean SKIP_DEV;
    
    private static class JsonFileFilter implements FilenameFilter {
        @Override
        public boolean accept (File dir, String name) {
            return name.toLowerCase().endsWith(".json");
        }
    }
    private static final Logger logger = Logger.getLogger(ProfileSignatureParametersDao.class.getName());

    protected String profileName;
    protected Boolean isInited = false;
    protected JsonObject defParam;

    JsonDao() {
        JSON_PATH = System.getProperty("profileconfig.jsonpath");
        SKIP_DEV = "true".equals(System.getProperty("profileconfig.skip_dev_profiles"));
    }
    protected void readProfiles(Map parameters, Class<? extends JsonObject> classType) throws IOException {
        File folder;
        if(JSON_PATH != null) {
            folder = new File(JSON_PATH + "/" + profileName);
        } else {
            folder = new File("../parameters/" + profileName);
        }

        if (!folder.exists()) {
            logger.log(Level.SEVERE, "Profiles dir does not exist: {0}", folder.getAbsolutePath());
            throw new IOException("Profiles directory does not exist");
        }
        File[] profileFiles = folder.listFiles(new JsonFileFilter());
        if (profileFiles == null || profileFiles.length == 0) {
            logger.log(Level.SEVERE, "Profiles dir is emtpy", folder.getAbsolutePath());
            throw new IOException("No profiles found");
        }
        logger.log(Level.INFO, "Reading " + profileName + " profiles from " + folder.getAbsolutePath());

        ObjectMapper mapper = new ObjectMapper();
        for(final File jsonFile : profileFiles) {
            logger.log(Level.INFO, "Parsing {0}", jsonFile.getName());
            JsonObject o = mapper.readValue(jsonFile, classType);
            if(!(SKIP_DEV && o.getDevOnlyProfile())) {
                parameters.put(o.getProfileId(), o);
                if(o.getIsDefault()) {
                    defParam = o;
                }
            }
        }
        isInited = true;
    }
}
