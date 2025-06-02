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

import java.io.*;
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
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

public class CertRequestBuilder {

  private KmsClient kms;
  private Config config;

  public CertRequestBuilder(File configFile) {
    config = new Config(configFile);
    kms = KmsClient.builder().build();
  }

  public void build() throws IOException {
    SubjectPublicKeyInfo subjectKeyInfo = getPublicKey();
    PublicKey publicKey = new JcaPEMKeyConverter().getPublicKey(subjectKeyInfo);
    JcaPKCS10CertificationRequestBuilder csrBuilder =
        new JcaPKCS10CertificationRequestBuilder(createName(), publicKey);
    ContentSigner signer = new KMSContentSigner();
    PKCS10CertificationRequest csr = csrBuilder.build(signer);
    try (PemWriter pemWriter =
        new PemWriter(new FileWriter(config.getConfiguration(CFG_CSR_OUTPUTFILE)))) {
      PemObjectGenerator objGen = new MiscPEMGenerator(csr);
      pemWriter.writeObject(objGen);
    }
  }

  private X500Name createName() {
    X500NameBuilder subject = new X500NameBuilder();
    subject.addRDN(
        X509ObjectIdentifiers.countryName, config.getConfiguration(CFG_CSR_COUNTRY_NAME));
    subject.addRDN(
        X509ObjectIdentifiers.stateOrProvinceName, config.getConfiguration(CFG_CSR_STATE));
    subject.addRDN(X509ObjectIdentifiers.localityName, config.getConfiguration(CFG_CSR_LOCALITY));
    subject.addRDN(X509ObjectIdentifiers.organization, config.getConfiguration(CFG_CSR_ORG));
    subject.addRDN(
        X509ObjectIdentifiers.organizationalUnitName, config.getConfiguration(CFG_CSR_ORG_UNIT));
    subject.addRDN(X509ObjectIdentifiers.commonName, config.getConfiguration(CFG_CSR_COMMON_NAME));
    return subject.build();
  }

  private SubjectPublicKeyInfo getPublicKey() {
    GetPublicKeyRequest req =
        GetPublicKeyRequest.builder().keyId(config.getConfiguration(CFG_KEY_ID)).build();
    GetPublicKeyResponse result = kms.getPublicKey(req);
    return SubjectPublicKeyInfo.getInstance(result.publicKey().asByteArray());
  }

  public static void main(String[] argv) throws Exception {
    // Get the config file.
    String config = argv[0];
    new CertRequestBuilder(new File(config)).build();
  }

  private class KMSContentSigner implements ContentSigner {
    private final ByteArrayOutputStream stream = new ByteArrayOutputStream();

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
        SignRequest request =
            SignRequest.builder()
                .keyId(config.getConfiguration(CFG_KEY_ID))
                .signingAlgorithm(KMS_SIG_ALG)
                .messageType(MessageType.RAW)
                .message(SdkBytes.fromByteArray(stream.toByteArray()))
                .build();
        SignResponse result = kms.sign(request);
        return result.signature().asByteArray();
      } catch (Exception e) {
        throw new RuntimeException("exception obtaining signature: " + e.getMessage(), e);
      }
    }
  }
}
