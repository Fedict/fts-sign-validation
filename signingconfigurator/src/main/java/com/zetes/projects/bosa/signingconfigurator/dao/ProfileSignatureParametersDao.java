package com.zetes.projects.bosa.signingconfigurator.dao;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileSignatureParameters;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ProfileSignatureParametersDao {
    @Value("${profileconfig.jsonpath}")
    private String JSON_PATH;
    
    private final Map<String, ProfileSignatureParameters> parameters;
    private ProfileSignatureParameters defParam;
    private boolean isInited = false;
    
    private class JsonFileFilter implements FilenameFilter {
        @Override
        public boolean accept (File dir, String name) {
            return name.toLowerCase().endsWith(".json");
        }
    }
    private static final Logger logger = Logger.getLogger(ProfileSignatureParametersDao.class.getName());
    
    ProfileSignatureParametersDao() {
        parameters = new LinkedHashMap();
    }
    void readProfiles() throws IOException {
        File folder;
        if(JSON_PATH != null) {
            folder = new File(JSON_PATH + "/signature");
        } else {
            folder = new File("../parameters/signature");
        }
        logger.log(Level.INFO, "Reading signature profiles from {0}", folder.getAbsolutePath());
        ObjectMapper mapper = new ObjectMapper();
        
        for(final File jsonFile : folder.listFiles(new JsonFileFilter())) {
            logger.log(Level.INFO, "Parsing {0}", jsonFile.getName());
            ProfileSignatureParameters p = mapper.readValue(jsonFile, ProfileSignatureParameters.class);
            parameters.put(p.getProfileId(), p);
            if(p.getIsDefault()) {
                defParam = p;
            }
        }
        isInited = true;
    }

    public ProfileSignatureParameters findById(String id) throws ProfileNotFoundException {
        if(!isInited) {
            try {
                readProfiles();
            } catch (IOException ex) {
                logger.log(Level.SEVERE, null, ex);
                throw new ProfileNotFoundException("Failed to load profiles");
            }
        }
        if(parameters.containsKey(id)) {
            return parameters.get(id);
        }
        throw new ProfileNotFoundException(String.format("%s not found", id));
    }
    public ProfileSignatureParameters findDefault() throws ProfileNotFoundException {
        if(!isInited) {
            try {
                readProfiles();
            } catch (IOException ex) {
                logger.log(Level.SEVERE, null, ex);
                throw new ProfileNotFoundException("Failed to load profiles");
            }
        }
        if(defParam != null) {
            return defParam;
        }
        throw new ProfileNotFoundException("Default profile not found");
    }
    public void deleteAll() {
        defParam = null;
        parameters.clear();
        isInited = true;
    }
    public void save(ProfileSignatureParameters p) {
        if(!isInited) {
            try {
                readProfiles();
            } catch(IOException ex) {
                logger.log(Level.SEVERE, null, ex);
            }
        }
        if(p.getIsDefault()) {
            defParam = p;
        }
        parameters.put(p.getProfileId(), p);
    }
}
