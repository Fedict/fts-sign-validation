package com.bosa.signandvalidation.service;

import org.springframework.core.io.ClassPathResource;

import java.awt.*;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImageOp;
import java.io.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import javax.naming.SizeLimitExceededException;

/**
 * Creates a PDF visible signature image based on a text and optionally an image (photo, icon, ...)
 * At the end, extra width or heigth is added in order to make the width/heigth ratio the same as for the field in the PDF (xPdfField/yPdfField)
 */
public class PdfImageBuilder {
	public static final int POS_TOP =    1;
	public static final int POS_BOTTOM = 2;
	public static final int POS_LEFT =   3;
	public static final int POS_RIGHT =  4;

	public static final int HALIGN_LEFT =   1;
	public static final int HALIGN_CENTER = 2;
	public static final int HALIGN_RIGHT =  3;

	public static final int VALIGN_TOP =    1;
	public static final int VALIGN_MIDDLE = 2;
	public static final int VALIGN_BOTTOM = 3;

	private static final int PADDING_HOR = 42;
	private static final int[] LINE_HEIGHTS = { 75, 152, 211 };
	private static final String SIGNATURE_FONT = "Roboto";
	private static final int[] SIGNATURE_FONT_SIZES = { 16, 58, 58 };

	private static final Color REMOTESIGN_TEXT_COLOR = new Color(0, 0x2B, 0x3E, 255);

	private static BufferedImage remoteSignImg;
	private static File fontDir;

	private static File getFontDir() {
		if (fontDir == null) {
			fontDir = new File("/opt/signvalidation/fonts/");
			if (!fontDir.exists()) fontDir = new File("../fonts/");
		}
		return fontDir;
	}


	/*
        export const RED: SignatureColor = { back: "#3B1923", border: "#492D35", text: "#B5B5B5", circle: "#471221", logo: "#542633" };
        export const BLACK: SignatureColor = { back: "#0C0F1E", border: "#2A2C39", text: "#FFFFFF", circle: "#0C0F1E", logo: "#2A2C39" };
        export const GREEN: SignatureColor = { back: "#162B20", border: "#293E32", text: "#B5B5B5", circle: "#162D20", logo: "#293E32" };
        export const WHITE: SignatureColor = { back: "#FFFFFF", border: "#E0E5E7", text: "#002B3E", circle: "#FFFFFF", logo: "#E0E5E7" };
	private static final Color BACKGROUND = Color.WHITE;
	private static final Color BORDER = new Color(0xE0E5E7);
	private static final Color TEXT = new Color(0x002B3E);
	private static final Color CIRCLE = Color.WHITE;
	private static final Color LOGO = new Color(0xE0E5E7);
    */
	private static final Color BACKGROUND = new Color(0x162B20);
	private static final Color BORDER = new Color(0x293E32);
	private static final Color TEXT = new Color(0xB5B5B5);
	private static final Color CIRCLE = new Color(0x162D20);
	private static final Color LOGO = new Color(0x293E32);

	public static byte[] makeRemoteSignPdfImage2(int imgX, int imgY, String mergedLines) throws Exception {
		BufferedImage bufferedImage =  new BufferedImage(imgX, imgY, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g2d = (Graphics2D) bufferedImage.getGraphics();
		Composite comp = AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.8F );
		g2d.setComposite(comp);

		// Calculate a general dimension for drawing
	    float dim = (float) Math.sqrt(imgX * imgY);

		// Background rounded corners
		float radius = dim / 16;
		g2d.setColor(BACKGROUND);
		g2d.fillRoundRect(0,0, imgX, imgY, (int) radius, (int) radius);

		// Clipping with rounded corners for circle and logo
		radius = dim / 20;
		float curX = dim / 20;
		float curY = curX;
		float curW = imgX - curX * 2;
		float curH = imgY - curY * 2;
		g2d.clip(new RoundRectangle2D.Float(curX, curY, curW, curH, (int) radius, (int) radius));

		// Draw gradient from left of the circle
		radius = Math.max(curH, curW) * 0.6F;
	    float circleX = curX + curW * 0.3F + radius;
		float circleY = curY + curH / 2;

		float[] fractions = { 0.0f, 1.0f };
		Color[] colors = { BACKGROUND, LOGO };
		LinearGradientPaint gp = new LinearGradientPaint(
				new Point2D.Float(curX, circleY),
				new Point2D.Float(circleX - radius * 0.7F, circleY),
				fractions, colors);
		g2d.setPaint(gp);
		g2d.fill(new Rectangle2D.Float(curX, curY, curW, curH));

		// Draw clipped circle
		g2d.setPaint(CIRCLE);
		g2d.fillArc((int) (circleX - radius), (int) (circleY - radius), (int) radius * 2, (int) radius * 2, 0, 360);

		// Draw clipped ".be" logo
		g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
	    char[] logo = ".be".toCharArray();
		g2d.setPaint(LOGO);
		g2d.setFont(getFont(SIGNATURE_FONT, (int) (dim / 2.5)));
		FontMetrics metrics = g2d.getFontMetrics();
		float lineWidth = metrics.charsWidth(logo, 0, logo.length);
		g2d.drawChars(logo, 0, logo.length, (int) (curX + curW * 0.9 - lineWidth), (int) (curY + curH * 1.02));

		// Get out of the clip
		g2d.dispose();

		g2d = (Graphics2D) bufferedImage.getGraphics();

		// Draw border with rounded corners
		float borderSize = dim / 80;
		if (borderSize > 4) borderSize = 4;
		g2d.setStroke(new BasicStroke(borderSize));

		radius = dim / 20;
		g2d.setColor(BORDER);
		g2d.drawRoundRect((int) curX, (int) curY, (int) curW, (int) curH, (int) radius, (int) radius);

	    float margin = dim / 16;
		curX += margin;
		curY += margin;
		curW -= margin * 4;
		curH -= margin * 2;

		// We split the text in 2 or 3 equal vertical areas
		// Find font where we can either draw the fullname on a single line or the first and last name on 2 lines with the same font size
		float textH;
		boolean singleLine;
		float fontSize = dim / 4;
		String[] lines = mergedLines.split("\n");
		int i = 0;
		char charLines[][] = new char[4][];
		for (String line : lines) charLines[i++] = line.toCharArray();
		char[] firstLine = (lines[2] + " " + lines[3]).toCharArray();
		while (true) {
			g2d.setFont(getFont(SIGNATURE_FONT, (int) fontSize));
			metrics = g2d.getFontMetrics();
			textH = metrics.getHeight();
			singleLine = metrics.charsWidth(firstLine, 0, firstLine.length) < curW && curH > textH * 2;
			if (singleLine) break;
			if (curH > textH * 3) {
				firstLine = charLines[2];
				char[] charLine = charLines[2].length > charLines[3].length ? charLines[2] : charLines[3];
				if (metrics.charsWidth(charLine, 0, charLine.length) < curW) break;
			}
			fontSize--;
			if (fontSize < 2) throw new SizeLimitExceededException();
		}

		g2d.setColor(TEXT);
		g2d.drawChars(firstLine, 0, firstLine.length, (int) curX, (int) (curY + textH * 2.1F));
		if (!singleLine) g2d.drawChars(charLines[3], 0, charLines[3].length, (int) curX, (int) (curY + textH * 3.2F));

		g2d.setFont(getFont(SIGNATURE_FONT, (int) (fontSize / 2.2F)));
		metrics = g2d.getFontMetrics();
		textH = metrics.getHeight();
		g2d.drawChars(charLines[0], 0, charLines[0].length, (int) curX, (int) (curY + textH));
		g2d.drawChars(charLines[1], 0, charLines[1].length, (int) curX, (int) (curY + textH * 2.2F));

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ImageIO.write(bufferedImage, "png", baos);
		g2d.dispose();
		return baos.toByteArray();
	}

	public static byte[] makeRemoteSignPdfImage(int targetX, int targetY, String text) throws Exception {
		if (remoteSignImg == null) {
			InputStream is = new ClassPathResource("/remote_sign.png").getInputStream();
			remoteSignImg = ImageIO.read(is);
		}

		// Create internal bitmap for rendering
		int imgX = remoteSignImg.getWidth();
		int imgY = remoteSignImg.getHeight();
		BufferedImage temp =  new BufferedImage(imgX, imgY, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g2d = (Graphics2D) temp.getGraphics();
		Composite comp = AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.8F );
		g2d.setComposite(comp);

		/* Render background as transparent */
		g2d.drawImage(remoteSignImg, 0, 0, imgX, imgY, null);

			// Calculate best sizes for fonts
		int index = 0;
		int[] lineHeights = new int[3];
		g2d.setColor(REMOTESIGN_TEXT_COLOR);
		g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
		for (String line : text.split("\n")) {
			char [] charLine = line.toCharArray();
			int minFontSize = SIGNATURE_FONT_SIZES[index];
			int lineWidth;

			// Calc min font size to fit the signature box for this line
			while(true) {
				g2d.setFont(getFont(SIGNATURE_FONT, minFontSize));
				FontMetrics metrics = g2d.getFontMetrics();
				lineWidth = metrics.charsWidth(charLine, 0, charLine.length);
				if (lineHeights[index] == 0) lineHeights[index] = metrics.getHeight();
				if (lineWidth < imgX - (PADDING_HOR * 2)) {
					g2d.drawChars(charLine, 0, charLine.length, PADDING_HOR, LINE_HEIGHTS[index]);
					break;
				}
				minFontSize--;
				if (minFontSize == 0) throw new SizeLimitExceededException("Font size impossible");
			}
			index++;
		}
		g2d.dispose();

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ImageIO.write(temp, "png", baos);
		g2d.dispose();
		return baos.toByteArray();
	}

	public static byte[] makePdfImage(
		int xPdfField, int yPdfField,
		String bgColor, int padding,
		String text, String textColor, int textPos, int textAlignH, int textAlignV, Font font,
		byte[] image) throws Exception {

		// Get image size (if present)
		int imgWidth = 0;
		int imgHeight = 0;
		BufferedImage img = null;
		if (null != image) {
			img = ImageIO.read(new ByteArrayInputStream(image));
			imgWidth = img.getWidth();
			imgHeight = img.getHeight();
		}

		// Get FontMetrics by using a temporary BufferedImage and Graphics2D
		BufferedImage tmp =  new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
		Graphics2D gr = (Graphics2D) tmp.getGraphics();
		gr.setFont(font);
		FontMetrics fontMetrics = gr.getFontMetrics();

		// Split the text in lines, compute the numer of pixels for each line (int[] linesLen)
		text = text.replace("\\n", "\n");
		String[] lines = text.split("\n");
		int lineCount = lines.length;
		char[][] linesChars = new char[lineCount][];
		int[] linesLen = new int[lineCount];
		int maxLineLen = 0;
		for (int i = 0; i < lineCount; i++) {
			linesChars[i] = lines[i].toCharArray();
			linesLen[i] = fontMetrics.charsWidth(linesChars[i], 0, linesChars[i].length);
			if (linesLen[i] > maxLineLen)
				maxLineLen = linesLen[i];
		}

		// Compute the horizontal positions of each line of the image
		int xTextStart = 0;
		int xImg = 0;
		if (null != image) {
			if (POS_BOTTOM == textPos || POS_TOP == textPos) {
				if (maxLineLen < imgWidth)
					xTextStart += (imgWidth - maxLineLen) / 2;
				else if (imgWidth < maxLineLen)
					xImg += (maxLineLen - imgWidth) / 2;
			}
			else if (POS_RIGHT == textPos)
				xTextStart += padding + imgWidth;
			else if (POS_LEFT == textPos)
				xImg += padding + maxLineLen;
		}
		int[] linesX = new int[lineCount];
		for (int i = 0; i < lineCount; i++) {
			if (HALIGN_LEFT == textAlignH)
				linesX[i] = xTextStart;                                  // LEFT
			else if (HALIGN_RIGHT == textAlignH)
				linesX[i] = xTextStart + maxLineLen - linesLen[i];       // RIGHT
			else
				linesX[i] = xTextStart + (maxLineLen - linesLen[i]) / 2; // CENTER
		}

		// Compute the vertical positions of each line and of the image
		int yTextStart = 0;
		int yImg = 0;
		int textHeigth = fontMetrics.getHeight();
		int fullTextHeight = lineCount * textHeigth;
		if (null != img) {
			if (POS_LEFT == textPos || POS_RIGHT == textPos) {
				if (fullTextHeight < imgHeight) {
					if (VALIGN_BOTTOM == textAlignV)
						yTextStart += imgHeight - fullTextHeight;        // BOTTOM
					else if (VALIGN_MIDDLE == textAlignV)
						yTextStart += (imgHeight - fullTextHeight) / 2;  // MIDDLE
					// else
					//      do nothing                                       // TOP
				}
				else if (imgHeight < fullTextHeight)
					xImg += (fullTextHeight - imgHeight) / 2;
			}
			else if (POS_BOTTOM == textPos)
				yTextStart = padding + imgHeight;
			else if (POS_TOP == textPos)
				yImg += padding + fullTextHeight;
		}
		yTextStart += textHeigth - fontMetrics.getDescent();
		int[] linesY = new int[lineCount];
		for (int i = 0; i < lineCount; i++)
			linesY[i] = yTextStart + i * textHeigth;

		// Compute the full width and length
		int fullWidth = 2 * padding; // padding left and right
		if (null == image)
			fullWidth += maxLineLen;
		else {
			if (POS_LEFT == textPos || POS_RIGHT == textPos)
				fullWidth += maxLineLen + padding + imgWidth; // image and text next to each other
			else
				fullWidth += Math.max(imgWidth, maxLineLen);
		}
		int fullHeight = 2 * padding; // padding top and bottom
		if (null == image)
			fullHeight += fullTextHeight;
		else {
			if (POS_TOP == textPos || POS_BOTTOM == textPos)
				fullHeight += fullTextHeight + padding + imgHeight; // image and text below each other
			else
				fullHeight += Math.max(imgHeight, fullTextHeight);
		}

		// Add extra with or extra height so that we get the same ratio as the width/height ratio of the PDF visible signature field
		int xOffs = padding;
		int xLen = fullWidth;
		int yOffs = padding;
		int yLen = fullHeight;
		if (fullWidth * yPdfField < fullHeight * xPdfField) {
			xLen = (fullHeight * xPdfField + yPdfField - 1) / yPdfField; // ceil((fullHeight * xPdfField) / yPdfField)
			xOffs += (xLen - fullWidth) / 2;
		}
		else if (fullWidth * yPdfField > fullHeight * xPdfField) {
			yLen = (fullWidth * yPdfField + xPdfField - 1) / xPdfField;  // ceil((fullWidth * yPdfField) / xPdfField)
			yOffs += (yLen - fullHeight) / 2;
		}

		// Create the resulting PDF image
		BufferedImage ret =  new BufferedImage(xLen, yLen, BufferedImage.TYPE_INT_ARGB);
		Graphics2D graphs = (Graphics2D) ret.getGraphics();
		// 1. Paint background
		graphs.setColor(makeColor(bgColor, true));
		graphs.fillRect(0, 0, xLen, yLen);
		// 2. Add text lines
		graphs.setFont(font);
		graphs.setColor(makeColor(textColor, false));
		for (int i = 0; i < lineCount; i++)
			graphs.drawChars(linesChars[i], 0, linesChars[i].length, xOffs + linesX[i], yOffs + linesY[i]);
		// 3. Add image
		if (null != img) {
			/* Render photo as transparent */
			Composite comp = AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.8F );
			graphs.setComposite(comp);
			graphs.drawImage(img, xOffs + xImg, yOffs + yImg, null);
		}

		// Convert to a byte array contain a PNG image
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ImageIO.write(ret, "png", baos);
		return baos.toByteArray();
	}

	/** Split the fontStr (e.g. "Serif/bi" into a font name (Serif) and font style (BOLD + ITALIC) */
	public static Object[] getFontNameAndStyle(String fontStr) {
		int fontStyle = Font.PLAIN;
		String fontName = "default";
		if (null != fontStr) {
			String[] parts = fontStr.split("/");
			if (parts.length == 1)
				fontName = fontStr;
			else {
				fontName = parts[0];
				if (parts[1].contains("b") || parts[1].contains("i"))
					fontStyle = 0;
				if (parts[1].contains("b"))
					fontStyle |= Font.BOLD;
				if (parts[1].contains("i"))
					fontStyle |= Font.ITALIC;
			}
		}
		return new Object[] {fontName, Integer.valueOf(fontStyle)};
	}

	/* Convert a color string (e.g. "#0077ff") into a Java Color object */
	static Color makeColor(String cc, boolean transparent) throws IllegalArgumentException {
		if (cc.length() != 7)
			throw new IllegalArgumentException("Invalid color code specified: " + cc);
		int r = Integer.parseInt(cc.substring(1, 3), 16);
		int g = Integer.parseInt(cc.substring(3, 5), 16);
		int b = Integer.parseInt(cc.substring(5, 7), 16);
		return new Color(r, g, b, transparent ? 160 : 255);
	}

	//////////////////////////// For testing ////////////////////////////

	public static void usage(String err) {
		if (null != err)
			System.out.println("ERR: " + err + "\n");
		System.out.println("Command line tool to make an image (out.png) for a PDF visible signature field");
		System.out.println("Parameters");
		System.out.println("  <xPdfField> <yPdfField> <bgColor> <padding> <text> <textColor> <textPos> <textAlignH> <textAlignV> <font> <fontSize> {<imageFile>}");
		System.out.println("In which:");
		System.out.println("  xPdfField, yPdfField: the width and height of the PDF visible signature field");
		System.out.println("  bgColor: background color, e.g. \"#0055ff\"");
		System.out.println("  padding: number of pixels for padding around the borders, e.g. 10");
		System.out.println("  text: text to be displayed, e.g. \"Signed by:\\nTöm Teçt\"");
		System.out.println("  textColor: text color, e.g. \"#00ff00\"");
		System.out.println("  textAlignH: text alignment: LEFT, CENTER or RIGHT");
		System.out.println("  textAlignV: text alignment: TOP, MIDDLE or BOTTOM");
		System.out.println("  font: font name (e.g. default, Serial, Courier, freescpt),");
		System.out.println("        optionally appended with /b (bold), /i (italic) or /bi (bold+italic)");
		System.out.println("  fontSize: font size in pixels, e.g. 24");
		System.out.println("  imageFile: optional image (photo, icon, ..) to add");
		System.out.println("Example:");
		System.out.println("  350 200 \"#ababab\" 10 \"Tîna Teçt\\n2021.09.20\" \"#0000dd\" TOP CENTER MIDDLE default/i 32 ../integration-tests/client/data/photo.jpg");
		System.out.println("  350 200 \"#ababab\" 10 \"Friedrich Förster Von Hindenburg\\n2021.09.20\" \"#0000dd\" TOP CENTER MIDDLE default/i 32 ../integration-tests/client/data/photo.jpg");
		System.out.println("  300 100 \"#ffffff\" 20 \" \\nSigned by:\\nCharlotte Désirée De La Montagne\\n \\nDate: 2021.09.20\\n \" \"#0000ff\" LEFT CENTER MIDDLE Courier 36");
		System.out.println("  300 100 \"#ffffff\" 20 \" \\nSigned by:\\nAn Vos\\n \\nDate: 2021.09.20\\n \" \"#0000ff\" LEFT CENTER MIDDLE Courier 36");
	}

	/* Disabled -> Sast false positive
	public static void main(String[] args) throws Exception {

		//for (String s : java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames())
		//	System.out.println("  " + s);

		// Parse cmd line args
		if (args.length < 11) {
			usage("Not enough arguments specified");
			return;
		}
		int xPdfField = Integer.parseInt(args[0]);
		int yPdfField = Integer.parseInt(args[1]);
		String bgColor = args[2];
		int padding = Integer.parseInt(args[3]);
		String text = args[4];
		String textColor = args[5];
		int textPos = getTextPos(args[6]);
		int textAlignH = getAlignH(args[7]);
		int textAlignV = getAlignV(args[8]);
		String fontStr = args[9];
		int fontSize = Integer.parseInt(args[10]);
		String imgFile = (args.length > 11) ? args[11] : null;

		Font font = getFont(fontStr, fontSize);

		byte[] img = (null == imgFile) ? null : readFile(new File(imgFile));

		byte[] out = makePdfImage(xPdfField, yPdfField, bgColor, padding, text, textColor, textPos, textAlignH, textAlignV, font, img);

		writeFile(new File("out.png"), out);
		System.out.println("Output written to out.png");
	}
	 */

	static int getTextPos(String pos) {
		if ("LEFT".equals(pos))
			return POS_LEFT;
		if ("RIGHT".equals(pos))
			return POS_RIGHT;
		if ("TOP".equals(pos))
			return POS_TOP;
		if ("BOTTOM".equals(pos))
			return POS_BOTTOM;
		throw new RuntimeException("Invalid value for textPos: " + pos);
	}

	static int getAlignH(String val) {
		if ("LEFT".equals(val))
			return HALIGN_LEFT;
		if ("CENTER".equals(val))
			return HALIGN_CENTER;
		if ("RIGHT".equals(val))
			return HALIGN_RIGHT;
		throw new RuntimeException("Invalid value for textAlignH: " + val);
	}

	static int getAlignV(String val) {
		if ("TOP".equals(val))
			return VALIGN_TOP;
		if ("MIDDLE".equals(val))
			return VALIGN_MIDDLE;
		if ("BOTTOM".equals(val))
			return VALIGN_BOTTOM;
		throw new RuntimeException("Invalid value for textAlignV: " + val);
	}

	static Font getFont(String fontStr, int fontSize) throws Exception {
		// Split the fontStr into fontName and fontType
		Object[] info = getFontNameAndStyle(fontStr);
		String fontName = (String) info[0];
		int fontType = ((Integer) info[1]).intValue();

		if (fontName.equals("default"))
			return new Font(null, fontType, fontSize);
		else {
			File fontFile = new File(getFontDir(), fontName + ".ttf");
			if (fontFile.exists()) {
				Font baseFont = Font.createFont(Font.TRUETYPE_FONT, fontFile);
				return baseFont.deriveFont(fontType, fontSize);
			}
			else
				return new Font(fontName, fontType, fontSize);
		}
	}

	static byte[] readFile(File f) throws Exception {
		byte[] ret = new byte[(int) f.length()];
		FileInputStream fis = new FileInputStream(f);
		fis.read(ret);
		fis.close();
		return ret;
	}

	static void writeFile(File f, byte[] buf) throws Exception {
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(buf);
		fos.close();
	}
}
