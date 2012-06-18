package com.lucasian.crypt.signer.api;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Map;

public interface Signer {

	public String sign(String signString, File certis, File keyis, String password) 
			throws Exception;
	
	public void validate(File cert) throws CertificateNotYetValidException, 
		CertificateExpiredException, FileNotFoundException, Exception;
	
	public Map<String, String> getCertData(File cert) 
			throws IOException, Exception;
	
}
