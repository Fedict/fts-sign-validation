package com.zetes.projects.bosa.signandvalidation.config;

/**
 * The contents of the "message" field of the json that is returned in case of an error
 */
public interface ErrorStrings {
	/** Signing cert has expired */
	static String SIGN_CERT_EXPIRED = "SIGN_CERT_EXPIRED";

	/** No or incomplete certificate chain */
	static String CERT_CHAIN_INCOMPLETE = "CERT_CHAIN_INCOMPLETE";

	/** No signing certificate provided */
	static String NO_SIGN_CERT = "NO_SIGN_CERT";

	/** Signing date out of bounds  */
	static String INVALID_SIG_DATE = "INVALID_SIG_DATE";

	/** Invalid user name or password */
	static String INVALID_S3_LOGIN = "INVALID_S3_LOGIN";

	/** The certificate is missing */
	static String NO_CERT_TO_VALIDATE = "NO_CERT_TO_VALIDATE";

	/** "DSSDocument is null" */
	static String NO_DOC_TO_VALIDATE = "NO_DOC_TO_VALIDATE";

	/** Required parameter token not provided */
	static String NO_TOKEN = "NO_TOKEN";

	/** Certificate (probably the signing cert) revoked */
	static String CERT_REVOKED = "CERT_REVOKED";

	/** Unexpected exception thown */
	static String INTERNAL_ERR = "INTERNAL_ERR";

	/** Document validation (after signing) failed */
	static String INVALID_DOC = "INVALID_DOC";

	/** Unknown signature profile */
	static String UNKNOWN_PROFILE = "UNKNOWN_PROFILE";

	/** Empty (null) parameter in request */
	static String EMPTY_PARAM = "EMPTY_PARAM";

	/** Invalid token in request */
	static String INVALID_TOKEN = "INVALID_TOKEN";

	/** Invalid signature level for document */
	static String INVALID_SIGNATURE_LEVEL = "INVALID_SIGNATURE_LEVEL";

	/** Invalid document type in request */
	static String INVALID_TYPE = "INVALID_TYPE";

	/** Coudln't parse request */
	static String PARSE_ERROR = "PARSE_ERROR";

	/** NN of the certificat is not in the allowed to sign list */
	static String NOT_ALLOWED_TO_SIGN = "NOT_ALLOWED_TO_SIGN";

	/** PDF signature field problem: not specified when needed or invalid value */
	static String ERR_PDF_SIG_FIELD = "ERR_PDF_SIG_FIELD";

	/** The delay between the getDataToSignForToken and the SignDocumentFroToken calls was larger than the timeout time defined in the "Token" (Pin code entry took too long)  */
	static String SIGN_PERIOD_EXPIRED = "SIGN_PERIOD_EXPIRED";
}
