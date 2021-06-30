package com.zetes.projects.bosa.signingconfigurator.dao;

import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileSignatureParameters;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.stereotype.Component;

@Component
public class ProfileSignatureParametersDao extends JsonDao {
    private final Map<String, ProfileSignatureParameters> parameters;
    private static final Logger logger = Logger.getLogger(ProfileSignatureParameters.class.getName());
        
    ProfileSignatureParametersDao() {
        parameters = new LinkedHashMap();
        profileName = "signature";
    }

    public ProfileSignatureParameters findById(String id) throws ProfileNotFoundException {
        if(!isInited) {
            try {
                readProfiles(parameters, ProfileSignatureParameters.class);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, null, ex);
                throw new ProfileNotFoundException("Failed to load profiles: " + ex.getMessage());
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
                readProfiles(parameters, ProfileSignatureParameters.class);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, null, ex);
                throw new ProfileNotFoundException("Failed to load profiles");
            }
        }
        if(defParam != null) {
            return (ProfileSignatureParameters)defParam;
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
                readProfiles(parameters, ProfileSignatureParameters.class);
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
