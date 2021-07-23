package be.fgov.bosa.ts.e2e;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.awt.AWTException;
import java.awt.Robot;
import java.awt.event.KeyEvent;
import java.io.File;
import java.util.stream.IntStream;

import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.StaleElementReferenceException;
import org.testng.Assert;
import org.testng.annotations.Test;

public class SignWithTokenHappyFlow extends BaseTest{

	@Test(description="Launches the site")
	public void launchSite(){
	  driver.get("https://mintest.ta.fts.bosa.belgium.be/");
	  assertEquals("FPS test signing service", driver.findElement(By.tagName("h1")).getText());
	}

	
	@Test(description="Start Sign test.pdf")
	public void startSignTestPdf(){
	  driver.findElement(By.linkText("test.pdf")).click();
	  
	  waitForHeaderText("Digital signature of 'test.pdf'");
	  
	  driver.findElement(By.id("documentReadCheckbox")).click();
	  
	  clickOnNextButton();
	}


	
	@Test(description="Wait until can enter pin")
	public void waitUntiPinCodeEntry(){
		waitForHeaderText("Enter pin code");
	}

	
	@Test(description="Can sign")
	public void testCanSign() throws AWTException{
		waitUntiPinCodeEntry();
		Robot robot = new Robot();
		
		String pincode = System.getProperty("bosa.ts_test.pin_code");
		assertNotNull(pincode, "The pincode must be defined, pass -Dbosa.ts_test.pin_code=<pincode> when running the test");
		assertTrue(pincode.length() == 4, "Pincode length is wrong");
		for (int i = 0; i < pincode.length(); i++) {
			char pinCodeChar = pincode.charAt(i);
			int keyEvent = pinCodeChar + 48; //use the numpad key stroke
			assertTrue(KeyEvent.VK_NUMPAD0 <= keyEvent && keyEvent <= KeyEvent.VK_NUMPAD9, "Pin code should only be from 0 to 9");
			robot.keyPress(keyEvent);
			robot.keyRelease(keyEvent);
		}
		
		clickOnNextButton();
		//signing should be in progress
		
		//wait until file is download
		File downloadedSignedFile = new File(downloadDirectory, "test.pdf");
		int timeout = 200;
		while(!downloadedSignedFile.exists() && timeout-- > 0) {
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
			}
		}
		assertTrue(downloadedSignedFile.exists(), "Signed File not downloaded: "+ downloadedSignedFile.getPath());
	}
	
	private boolean isRedirected() {
		return driver.getCurrentUrl().startsWith("https://mintest");
	}
	
	@Test(description = "User is redirected")
	public void testIsRedirected() {
		int timeout = 200;
		while(!isRedirected() && timeout-- > 0) {
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
			}
		}
		assertTrue(isRedirected(), "Expect to be redirected but was: " + driver.getCurrentUrl());
	}

	
	private void waitForHeaderText(String expectedHeader) {
		assertNotNull(expectedHeader);
		int timeout = 100;
		while(!getHeaderText().equalsIgnoreCase(expectedHeader) && timeout -- > 0) {
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {
			}
		}
		assertEquals(getHeaderText().toLowerCase(), expectedHeader.toLowerCase());
	}
	
	private String getHeaderText() {
		try {
			return driver.findElement(By.cssSelector(".card-header")).getText();
		}catch (NoSuchElementException e) {
			return "";
		}catch(StaleElementReferenceException e) {
			return "";
		}
	}

	private void clickOnNextButton() {
		int timeout = 100;
		while(!driver.findElement(By.id("button_next")).isEnabled() && timeout-- > 0) {
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		assertTrue(driver.findElement(By.id("button_next")).isEnabled(), "The next button is disabled");
		driver.findElement(By.id("button_next")).click();
	}
}
