package io.github.quotidianennui;

import static io.github.quotidianennui.Config.CFG_CSR_COMMON_NAME;
import static io.github.quotidianennui.Config.CFG_CSR_COUNTRY_NAME;
import static io.github.quotidianennui.Config.CFG_CSR_LOCALITY;
import static io.github.quotidianennui.Config.CFG_CSR_ORG;
import static io.github.quotidianennui.Config.CFG_CSR_ORG_UNIT;
import static io.github.quotidianennui.Config.CFG_CSR_OUTPUTFILE;
import static io.github.quotidianennui.Config.CFG_CSR_STATE;
import static io.github.quotidianennui.Config.CFG_KEY_ID;
import static io.github.quotidianennui.Config.KMS_SIG_ALG;
import static io.github.quotidianennui.Config.SIG_ALG_ID;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.amazonaws.services.kms.model.MessageType;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;

public class CertRequestBuilder {

  private transient AWSKMS kms;
  private transient Config config;

  public CertRequestBuilder(File configFile) {
    config = new Config(configFile);
    kms = AWSKMSClientBuilder.standard().build();
  }

  public void build() throws Exception {
    SubjectPublicKeyInfo subjectKeyInfo = getPublicKey();
    PublicKey publicKey = new JcaPEMKeyConverter().getPublicKey(subjectKeyInfo);
    JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(createName(), publicKey);
    ContentSigner signer = new KMSContentSigner();
    PKCS10CertificationRequest csr = csrBuilder.build(signer);
    try (PemWriter pemWriter = new PemWriter(new FileWriter(config.getConfiguration(CFG_CSR_OUTPUTFILE)))) {
      PemObjectGenerator objGen = new MiscPEMGenerator(csr);
      pemWriter.writeObject(objGen);
    }
  }

  private X500Name createName() {
    X500NameBuilder subject = new X500NameBuilder();
    subject.addRDN(X509ObjectIdentifiers.countryName, config.getConfiguration(CFG_CSR_COUNTRY_NAME));
    subject.addRDN(X509ObjectIdentifiers.stateOrProvinceName, config.getConfiguration(CFG_CSR_STATE));
    subject.addRDN(X509ObjectIdentifiers.localityName, config.getConfiguration(CFG_CSR_LOCALITY));
    subject.addRDN(X509ObjectIdentifiers.organization, config.getConfiguration(CFG_CSR_ORG));
    subject.addRDN(X509ObjectIdentifiers.organizationalUnitName, config.getConfiguration(CFG_CSR_ORG_UNIT));
    subject.addRDN(X509ObjectIdentifiers.commonName, config.getConfiguration(CFG_CSR_COMMON_NAME));
    return subject.build();
  }


  private SubjectPublicKeyInfo getPublicKey() throws Exception {
    GetPublicKeyRequest req = new GetPublicKeyRequest().withKeyId(config.getConfiguration(CFG_KEY_ID));
    GetPublicKeyResult result = kms.getPublicKey(req);
    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(result.getPublicKey().array());
    return keyInfo;
  }

  public static void main(String[] argv) throws Exception {
    // Get the config file.
    String config = argv[0];
    new CertRequestBuilder(new File(config)).build();
  }


  private class KMSContentSigner implements ContentSigner {
    private ByteArrayOutputStream stream = new ByteArrayOutputStream();

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return SIG_ALG_ID;
    }

    @Override
    public OutputStream getOutputStream() {
      return stream;
    }

    @Override
    public byte[] getSignature() {
      try {
        SignRequest request =  new SignRequest()
            .withKeyId(config.getConfiguration(CFG_KEY_ID))
            .withSigningAlgorithm(KMS_SIG_ALG)
            .withMessageType(MessageType.RAW)
            .withMessage(ByteBuffer.wrap(stream.toByteArray()));
        SignResult result = kms.sign(request);
        return result.getSignature().array();
      } catch (Exception e) {
        throw new RuntimeException("exception obtaining signature: " + e.getMessage(), e);
      }
    }
  };
}
