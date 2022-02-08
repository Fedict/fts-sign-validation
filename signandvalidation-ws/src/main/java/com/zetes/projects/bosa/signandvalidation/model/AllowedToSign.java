package com.zetes.projects.bosa.signandvalidation.model;

/**
 * Define a citizen through it's national number that is allowed to sign.
 * <p>
 * The field must have the same syntaxe as the "SERIALNUMBER" defined inside the citizen certificate 
 *
 * @author Christophe
 */
public class AllowedToSign {
    private String nn;

    public AllowedToSign() {
    }
    public AllowedToSign(String nn) {
        this.nn = nn;
    }
    /**
    * Returns the national register number. 
    *
    * @return the national register number
    */
    public String getNN() {
        return nn;
    }
    /**
    * Set the national register number.
    * It must have the same syntaxe as the "SERIALNUMBER" defined inside the citizen certificate
    *
    * @param  nn  the national register number
    */
    public void setNN(String nn) {
        this.nn = nn;
    }
}
