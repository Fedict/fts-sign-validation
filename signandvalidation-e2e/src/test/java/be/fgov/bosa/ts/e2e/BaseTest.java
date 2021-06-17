package be.fgov.bosa.ts.e2e;

import java.io.File;
import java.util.HashMap;

import org.openqa.grid.internal.utils.configuration.StandaloneConfiguration;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.remote.server.SeleniumServer;
import org.testng.ITestContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeSuite;

public abstract class BaseTest {
	protected SeleniumServer server;
	protected WebDriver driver;
	protected File downloadDirectory;

	@BeforeSuite(alwaysRun = true)
	public void setupBeforeSuite(ITestContext context) {
		String seleniumHost = context.getCurrentXmlTest().getParameter("selenium.host");
		String seleniumPort = context.getCurrentXmlTest().getParameter("selenium.port");
		String seleniumBrowser = context.getCurrentXmlTest().getParameter("selenium.browser");
		String seleniumUrl = context.getCurrentXmlTest().getParameter("selenium.url");

		StandaloneConfiguration config = new StandaloneConfiguration();
		config.host = seleniumHost;
		if(seleniumPort != null) {
			config.port = Integer.parseInt(seleniumPort);
		}
		try {
			server = new SeleniumServer(config);
			server.boot();
		} catch (Exception e) {
			throw new IllegalStateException("Can't start selenium server", e);
		}
		System.setProperty("webdriver.chrome.driver", 
				BaseTest.class.getClassLoader().getResource("browsers/chrome91/win/chromedriver.exe").getPath());
		
		ChromeOptions options = new ChromeOptions ();
		options.addExtensions (new File(BaseTest.class.getClassLoader().getResource("extention/chrome/BeIDConnect_v0.0.6.crx").getPath()));
		downloadDirectory = new File(System.getProperty("java.io.tmpdir"), "bosa_ts_tests");
		downloadDirectory.mkdirs();
		HashMap<String, Object> chromePrefs = new HashMap<String, Object>();
		chromePrefs.put("download.default_directory", downloadDirectory.getPath());
		options.setExperimentalOption("prefs", chromePrefs);
		driver = new ChromeDriver(options);
	}
	
	@BeforeClass
	public void cleanDownloadDirectory() {
		//empty directory
		for (File subfile : downloadDirectory.listFiles()) {
			subfile.delete();
		}
	}

	@AfterSuite(alwaysRun = true)
	public void setupAfterSuite() {
		//driver.close();
		server.stop();
	}

}
