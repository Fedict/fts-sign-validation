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

	/** Certificate (probably the signing cert) revoked */
	public static String CERT_REVOKED = "CERT_REVOKED";

	/** Unexpected exception thown */
	public static String INTERNAL_ERR = "INTERNAL_ERR";

	/** Document validation (after signing) failed */
	public static String INVALID_DOC = "INVALID_DOC";

	/** Unknown signature profile */
	public static String UNKNOWN_PROFILE = "UNKNOWN_PROFILE";

	/** Empty (null) parameter in request */
	public static String EMPTY_PARAM = "EMPTY_PARAM";

	/** Invalid token in request */
	public static String INVALID_TOKEN = "INVALID_TOKEN";

	/** Invalid signature level for document */
	public static String INVALID_SIGNATURE_LEVEL = "INVALID_SIGNATURE_LEVEL";

	/** Invalid document type in request */
	public static String INVALID_TYPE = "INVALID_TYPE";

	/** Coudln't parse request */
	public static String PARSE_ERROR = "PARSE_ERROR";

	/** NN of the certificat is not in the allowed to sign list */
	public static String NOT_ALLOWED_TO_SIGN = "NOT_ALLOWED_TO_SIGN";

	/** PDF signature field problem: not specified when needed or invalid value */
	public static String ERR_PDF_SIG_FIELD = "ERR_PDF_SIG_FIELD";

	/** The delay between the getDataToSignForToken and the SignDocumentFroToken calls was larger than the timeout time defined in the "Token" (Pin code entry took too long)  */
	public static String SIGN_PERIOD_EXPIRED = "SIGN_PERIOD_EXPIRED";
}
