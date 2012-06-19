package com.lucasian.crypt.signer.api;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Map;

public interface Signer {

	public String sign(String signString, InputStream certStream, 
			InputStream keyStream, String password) throws Exception;
	
	public void validate(InputStream certStream) throws CertificateNotYetValidException, 
	CertificateExpiredException, Exception;
	
	public Map<String, String> getCertData(InputStream certStream) 
			throws IOException, Exception;
	
}
