package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.*;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.HashMap;
import java.util.LinkedHashMap;

/** Contents of the PDF Signature Profile, a JSON file that is sent by the FPS to the S3 server */
public class PdfSignatureProfile {

	// V1 & V2 properties
	@Schema(example = "#D0D0D0", description = "If version=1 : background color of both the text and the signature, if version=2 : background color of the text" )
	public String bgColor;
	@Schema(example = "'fr'='Signé par %g', 'en'='Signed by %g'", description = "A map of language and Strings to draw" )
	public HashMap<String, String> texts = new LinkedHashMap<>();
	@Schema(example = "16", description = "Size of text to draw." )
	public Integer textSize;
	@Schema(example = "Serif/bi", description = "Font to use (format : <FontName>/<b><i>)" )
	public String font;
	@Schema(example = "10", description = "Number of pixels between the box borders and the text of the signature" )
	public Integer textPadding;
	@Schema(description = "How the signature text will be aligned horizontally" )
	public SignerTextHorizontalAlignment textAlignH;
	@Schema(description = "How the signature text will be aligned vertically" )
	public SignerTextVerticalAlignment textAlignV;
	@Schema(description = "Where in the box will the signature text be displayed" )
	public SignerTextPosition textPos;
	@Schema(example = "#000000", description = "Color of the text" )
	public String textColor;
	@Schema(example = "1,100,150,200,230", description = "In case the psfC (see parent object) value is set to 'default' use this value as psfC" )
	public String defaultCoordinates;
	@Schema(example = "400", description = "Resolution of the image" )
	public Integer imageDpi;
	@Schema(description = "The base64 encoded image to embed in the signature. If value is the Base64 encoded 'default' string, use the default signature icon" )
	public byte[] image;

	// V2 properties
	@Schema(example = "2", description = "Version if this record. Default is '1'" )
	public Integer version;
	@Schema(description = "How the text will behave in case it does not fit a line." )
	public TextWrapping textWrapping;
	@Schema(description = "How to draw the image in case it does not fit the signature box" )
	public ImageScaling imageScaling;
	@Schema(description = "Where to place the signature box on the page" )
	public VisualSignatureAlignmentHorizontal horizAlignment;
	@Schema(description = "Where to place the signature box on the page" )
	public VisualSignatureAlignmentVertical vertAlignment;
	@Schema(example = "#000000", description = "Color of the signature box" )
	public String bodyBgColor;
	@Schema(description = "Rotation of the signature box" )
	public VisualSignatureRotation rotation;
	@Schema(example = "50", description = "Zoom level (%) of the signature. Default is 100%" )
	public Integer zoom;
}
