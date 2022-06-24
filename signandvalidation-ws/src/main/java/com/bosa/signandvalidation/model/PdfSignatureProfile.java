package com.bosa.signandvalidation.model;

import java.util.LinkedHashMap;

/** Contents of the PDF Signature Profile, a JSON file that is sent by the FPS to the S3 server */
public class PdfSignatureProfile {
	public String bgColor;			// in V1 = BG color of both the text and the signature
									// in V2 = BG color of both the text
	public LinkedHashMap<String, String> texts;
	public Integer textSize;
	public String font;				// Font to use (format : <FontName>/<b><i>. Sample : "Serif/bi"
	public Integer textPadding;
	public String textAlignH;
	public String textAlignV;
	public String textPos;
	public String textColor;
	public String defaultCoordinates;
	public Integer imageDpi;
	public byte[] image;
    public Integer version;

	// V2 properties
	public String imageScaling;
	public String horizAlignment;
	public String vertAlignment;
	public String bodyBgColor;
	public String rotation;
	public Integer zoom;
    public String textWrapping;
}
