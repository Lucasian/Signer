package com.lucasian.crypt.signer;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;

public class CertData implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6342658890124566795L;
	protected Map<String, String> personData;
	protected String serialNumber;
	protected Date expirationDate;
	
	
	public Map<String, String> getPersonData() {
		return personData;
	}
	public void setPersonData(Map<String, String> personData) {
		this.personData = personData;
	}
	public String getSerialNumber() {
		return serialNumber;
	}
	public void setSerialNumber(String serialNumber) {
		this.serialNumber = serialNumber;
	}
	public Date getExpirationDate() {
		return expirationDate;
	}
	public void setExpirationDate(Date expirationDate) {
		this.expirationDate = expirationDate;
	}
	

}
