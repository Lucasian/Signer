package com.lucasian.crypt.signer;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

public interface Signer {

	public String sign(String signString, InputStream certStream, 
			InputStream keyStream, String password) throws Exception;
	
	public void verifyCert(InputStream certStream) throws CertificateNotYetValidException, 
	CertificateExpiredException, Exception;
	
	public boolean validate(InputStream certStream, String signString, String signedString) throws 
	CertificateNotYetValidException, CertificateExpiredException, Exception;
	
	public CertData getCertData(InputStream certStream) 
			throws IOException, Exception;
	
}
