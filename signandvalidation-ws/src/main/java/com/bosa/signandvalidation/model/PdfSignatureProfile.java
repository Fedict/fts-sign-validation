package com.bosa.signandvalidation.model;

import java.util.LinkedHashMap;

/** Contents of the PDF Signature Profile, a JSON file that is sent by the FPS to the S3 server */
public class PdfSignatureProfile {
	public String bgColor;
	public LinkedHashMap<String, String> texts;
	public Integer textSize;
	public String font;
	public Integer textPadding;
	public String textAlignH;
	public String textAlignV;
	public String textPos;
	public String textColor;
	public String defaultCoordinates;
	public Integer imageDpi;
	public byte[] image;
}
