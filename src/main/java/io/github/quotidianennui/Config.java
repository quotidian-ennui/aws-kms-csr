package io.github.quotidianennui;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;

public class Config {

  public static final String CFG_KEY_ID = "kms.keyId";
  public static final String CFG_CSR_OUTPUTFILE = "csr.outputFile";
  public static final String CFG_CSR_COMMON_NAME = "csr.commonName";
  public static final String CFG_CSR_ORG_UNIT = "csr.organisationalUnit";
  public static final String CFG_CSR_ORG = "csr.organisation";
  public static final String CFG_CSR_LOCALITY = "csr.locality";
  public static final String CFG_CSR_STATE = "csr.stateOrProvinceName";
  public static final String CFG_CSR_COUNTRY_NAME = "csr.countryName";
  public static final String SIG_ALG = "SHA256WithRSA";
  public static final SigningAlgorithmSpec KMS_SIG_ALG = SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;

  public static final AlgorithmIdentifier SIG_ALG_ID = new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_ALG);

  private static final Properties DEFAULTS;

  static {
    DEFAULTS = new Properties();
    DEFAULTS.setProperty(CFG_CSR_OUTPUTFILE, "./build/my-csr.csr");
    DEFAULTS.setProperty(CFG_CSR_COMMON_NAME, "MyCommonName");
    DEFAULTS.setProperty(CFG_CSR_ORG_UNIT, "MyOrganisationUnit");
    DEFAULTS.setProperty(CFG_CSR_ORG, "MyOrganisation");
    DEFAULTS.setProperty(CFG_CSR_LOCALITY, "MyTown");
    DEFAULTS.setProperty(CFG_CSR_STATE, "MyCounty");
    DEFAULTS.setProperty(CFG_CSR_COUNTRY_NAME, "GB");
  }
  
  private Properties configuration;

  public Config(File file) {
    configuration = loadQuietly(file);
  }

  public String getConfiguration(String key) {
    return configuration.getProperty(key);
  }

  public static Properties loadQuietly(File in) {
    return loadQuietly(() -> {
      return new FileInputStream(in); // should have used Supplier but bah, exceptions.
    });
  }

  public static Properties loadQuietly(PropertyInputStream e) {
    Properties result = new Properties(DEFAULTS);
    try (InputStream in = e.openStream()) {
      result.load(in);
    } catch (Exception ignored) {
    }
    return result;
  }

  @FunctionalInterface
  public interface PropertyInputStream {
    InputStream openStream() throws IOException;
  }
}
