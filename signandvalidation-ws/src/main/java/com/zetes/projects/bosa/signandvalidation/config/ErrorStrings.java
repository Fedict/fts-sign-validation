package com.zetes.projects.bosa.signandvalidation.config;

/**
 * The contents of the "message" field of the json that is returned in case of an error
 */
public interface ErrorStrings {
	/** Signing cert has expired */
	public static String SIGN_CERT_EXPIRED = "SIGN_CERT_EXPIRED";

	/** No or incomplete certificate chain */
	public static String CERT_CHAIN_INCOMPLETE = "CERT_CHAIN_INCOMPLETE";

	/** No signing certificate provided */
	public static String NO_SIGN_CERT = "NO_SIGN_CERT";

	/** Signing date out of bounds  */
	public static String INVALID_SIG_DATE = "INVALID_SIG_DATE";

	/** Invalid user name or password */
	public static String INVALID_S3_LOGIN = "INVALID_S3_LOGIN";

	/** The certificate is missing */
	public static String NO_CERT_TO_VALIDATE = "NO_CERT_TO_VALIDATE";

	/** "DSSDocument is null" */
	public static String NO_DOC_TO_VALIDATE = "NO_DOC_TO_VALIDATE";

	/** Required parameter token not provided */
	public static String NO_TOKEN = "NO_TOKEN";
}
