package com.lucasian.crypt.signer;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.ssl.PKCS8Key;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

public class BouncyTest {

	private String theCert = "/data/workspaces/just-cloud/signer/signer-bouncy/certs/xxxx.cer";
	private String theKey = "/data/workspaces/just-cloud/signer/signer-bouncy/certs/xxx.key";
	private String thePassword = "xxxx";

	@BeforeClass
	public static void preload() {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
	}

	@Test
	public void testGetData() throws Exception {
		X509Certificate cert = readCert();

		X509Principal principal = (X509Principal) cert.getSubjectDN();

		Map<String, String> results = new HashMap<String, String>();

		@SuppressWarnings("unchecked")
		Vector<ASN1ObjectIdentifier> oids = principal.getOIDs();
		@SuppressWarnings("unchecked")
		Vector<String> value = principal.getValues();

		for (int i = 0; i < oids.size(); i++) {
			// 2.5.4.41 is the name
			// 2.5.4.5 is the CURP
			// 2.5.4.45 is the RFC
			results.put(oids.get(i).getId(), value.get(i));
		}

		System.out.println(results);

		// cert.checkValidity();

	}

	@Test
	public void signKey() throws Exception {
		PKCS8Key key = new PKCS8Key(readBytes(new File(theKey)),
				thePassword.toCharArray());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(
				key.getDecryptedBytes());
		String alg = null;

		if (key.isDSA()) {
			alg = "DSA";
		} else if (key.isRSA()) {
			alg = "RSA";
		} else {
			throw new Exception("Unknown algorithm");
		}

		PrivateKey pk = KeyFactory.getInstance(alg, "BC").generatePrivate(spec);
		X509Certificate cert = readCert();
		PublicKey puk = cert.getPublicKey();
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
				.find("SHA1withRSA");

		ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA")
				.setProvider("BC").build(pk);

		String signString = "Vamos a firmar";

		signer.getOutputStream().write(signString.getBytes());
		String signedString = new String(Hex.encode(signer.getSignature()));
		System.out.printf("The signature of %s is %s\n", signString,
				signedString);

		ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
				.setProvider("BC").build(puk);

		ContentVerifier verifier = verifierProvider.get(sigAlgId);
		verifier.getOutputStream().write(signString.getBytes());
		assertTrue(verifier.verify(Hex.decode(signedString.getBytes())));
	}

	private byte[] readBytes(File file) throws Exception {
		InputStream is = new FileInputStream(file);

		// Get the size of the file
		long length = file.length();

		// You cannot create an array using a long type.
		// It needs to be an int type.
		// Before converting to an int type, check
		// to ensure that file is not larger than Integer.MAX_VALUE.
		if (length > Integer.MAX_VALUE) {
			// File is too large
		}

		// Create the byte array to hold the data
		byte[] bytes = new byte[(int) length];

		// Read in the bytes
		int offset = 0;
		int numRead = 0;
		while (offset < bytes.length
				&& (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
			offset += numRead;
		}

		// Ensure all the bytes have been read in
		if (offset < bytes.length) {
			throw new IOException("Could not completely read file "
					+ file.getName());
		}

		// Close the input stream and return bytes
		is.close();
		return bytes;
	}

	private X509Certificate readCert() throws Exception {
		InputStream is = new FileInputStream(theCert);
		X509Certificate cert;
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509",
					"BC");
			cert = (X509Certificate) cf.generateCertificate(is);

			System.out.println(cert);

		} finally {
			if (is != null) {
				is.close();
			}

		}
		return cert;
	}

}
