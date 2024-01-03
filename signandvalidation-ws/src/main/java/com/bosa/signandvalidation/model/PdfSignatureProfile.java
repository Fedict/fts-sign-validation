package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.*;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.HashMap;
import java.util.LinkedHashMap;

/** Contents of the PDF Signature Profile, a JSON file that is sent by the FPS to the S3 server */
public class PdfSignatureProfile {
	public String bgColor;			// in V1 = BG color of both the text and the signature
									// in V2 = BG color of the text
	public HashMap<String, String> texts = new LinkedHashMap<>();
	public Integer textSize;
	public String font;				// Font to use (format : <FontName>/<b><i>. Sample : "Serif/bi"
	public Integer textPadding;
	public SignerTextHorizontalAlignment textAlignH;
	public SignerTextVerticalAlignment textAlignV;
	public SignerTextPosition textPos;
	public String textColor;
	public String defaultCoordinates;
	public Integer imageDpi;
	public byte[] image;
    public Integer version;

	// V2 properties
	public TextWrapping textWrapping;
	public ImageScaling imageScaling;
	public VisualSignatureAlignmentHorizontal horizAlignment;
	public VisualSignatureAlignmentVertical vertAlignment;
	public String bodyBgColor;
	public VisualSignatureRotation rotation;
	public Integer zoom;
}
