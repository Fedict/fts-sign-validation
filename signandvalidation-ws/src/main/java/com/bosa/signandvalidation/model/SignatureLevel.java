package com.bosa.signandvalidation.model;

/* This class was created because of the below lines found in "eu.europa.esig.dss.enumerations.SignatureLevel"

    public static SignatureLevel valueByName(String name) {
        return valueOf(name.replace('-', '_'));
    }

    public String toString() {
        return super.toString().replace('_', '-');
    }

   As those enums are exposed swagger displays the enum values as "XML-NOT-ETSI" instead of "XML_NOT_ETSI"
   This is because of the "toString()"
   But, as swagger does not use the "DSS defined" "valueByName" the application does not accept the "XML-NOT-ETSI"
   values.
   This is a DSS issue as their objects can't be exposed with generic tools.

   A git Report was submitted to change swagger behaviour and start using "name()" instead of "toString()" but is was rejected
   A more complex alternative solution was to use a Swagger ModelConverter to fix the issue
 */

public enum SignatureLevel {
    XML_NOT_ETSI,
    XAdES_BES,
    XAdES_EPES,
    XAdES_T,
    XAdES_LT,
    XAdES_C,
    XAdES_X,
    XAdES_XL,
    XAdES_A,
    XAdES_BASELINE_B,
    XAdES_BASELINE_T,
    XAdES_BASELINE_LT,
    XAdES_BASELINE_LTA,
    CMS_NOT_ETSI,
    CAdES_BES,
    CAdES_EPES,
    CAdES_T,
    CAdES_LT,
    CAdES_C,
    CAdES_X,
    CAdES_XL,
    CAdES_A,
    CAdES_BASELINE_B,
    CAdES_BASELINE_T,
    CAdES_BASELINE_LT,
    CAdES_BASELINE_LTA,
    PDF_NOT_ETSI,
    PKCS7_B,
    PKCS7_T,
    PKCS7_LT,
    PKCS7_LTA,
    PAdES_BASELINE_B,
    PAdES_BASELINE_T,
    PAdES_BASELINE_LT,
    PAdES_BASELINE_LTA,
    JSON_NOT_ETSI,
    JAdES_BASELINE_B,
    JAdES_BASELINE_T,
    JAdES_BASELINE_LT,
    JAdES_BASELINE_LTA,
    UNKNOWN;

    public eu.europa.esig.dss.enumerations.SignatureLevel toDSS() {
        return eu.europa.esig.dss.enumerations.SignatureLevel.valueOf(this.toString());
    }

    public static SignatureLevel fromDss(eu.europa.esig.dss.enumerations.SignatureLevel in) {
        // Avoid using "eu.europa.esig.dss.enumerations.SignatureLevel.toString()"
        return valueOf(in.name());
    }

}
