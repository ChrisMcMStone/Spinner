import java.io.FileInputStream;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.util.Properties;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration class 
 * 
 */
public class Config {
    String dnsIP;
    String censysID;
    String censysSecret;
    String[] allowList;
	
	public Config(String configFilename, String whitelistFilename) throws Exception {
		Properties properties = new Properties();
		InputStream configInput = new FileInputStream(configFilename);
		properties.load(configInput);
		loadProperties(properties, whitelistFilename);
	}

	public void loadProperties(Properties properties, String whitelistFilename) throws Exception {
		dnsIP = properties.getProperty("dns");
		censysID = properties.getProperty("censysID");
		censysSecret = properties.getProperty("censysSecret");
        if(whitelistFilename != null) {
            BufferedReader in = new BufferedReader(new FileReader(whitelistFilename));
            String str;
            List<String> list = new ArrayList<String>();
            while((str = in.readLine()) != null){
                list.add(str);
            }
            allowList = list.toArray(new String[0]);
        } else {
            allowList = new String[]{};
        }
	}
}
