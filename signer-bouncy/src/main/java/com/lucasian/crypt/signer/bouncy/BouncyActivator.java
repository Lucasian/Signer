package com.lucasian.crypt.signer.bouncy;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;


public class BouncyActivator implements BundleActivator {

	@Override
	public void start(BundleContext context) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Override
	public void stop(BundleContext context) throws Exception {
		Security.removeProvider("BC");
	}

}
