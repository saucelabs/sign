/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package s;

import sun.misc.BASE64Encoder;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.jar.*;
import java.util.regex.Pattern;

/**
 * Command line tool to sign JAR files (including APKs and OTA updates) in a way
 * compatible with the mincrypt verifier, using SHA1 and RSA keys.
 */
@SuppressWarnings("restriction")
public class Sign {
	private static final String CERT_SF_NAME = "META-INF/CERT.SF";
	private static final String CERT_RSA_NAME = "META-INF/CERT.RSA";

	private static final String OTACERT_NAME = "META-INF/com/android/otacert";

	// Files matching this pattern are not copied to the output.
	private static Pattern stripPattern = Pattern
			.compile("^META-INF/(.*)[.](SF|RSA|DSA)$");

	private static X509Certificate readPublicKey() throws IOException,
			GeneralSecurityException {
		final InputStream publicKeyFileIS = new ByteArrayInputStream(publicBytes);
		final CertificateFactory cf = CertificateFactory.getInstance("X.509");
		return (X509Certificate) cf.generateCertificate(publicKeyFileIS);
	}

	/** Read a PKCS 8 format private key. */
	private static PrivateKey readPrivateKey() throws IOException,
			GeneralSecurityException {
		KeySpec spec = new PKCS8EncodedKeySpec(privateBytes);

		try {
			return KeyFactory.getInstance("RSA").generatePrivate(spec);
		} catch (InvalidKeySpecException ex) {
			return KeyFactory.getInstance("DSA").generatePrivate(spec);
		}

	}

	/** Add the SHA1 of every file to the manifest, creating it if necessary. */
	private static Manifest addDigestsToManifest(JarFile jar) throws IOException,
			GeneralSecurityException {
		Manifest input = jar.getManifest();
		Manifest output = new Manifest();
		Attributes main = output.getMainAttributes();
		if (input != null) {
			main.putAll(input.getMainAttributes());
		} else {
			main.putValue("Manifest-Version", "1.0");
		}

		BASE64Encoder base64 = new BASE64Encoder();
		MessageDigest md = MessageDigest.getInstance("SHA1");
		byte[] buffer = new byte[4096];
		int num;

		// We sort the input entries by name, and add them to the
		// output manifest in sorted order. We expect that the output
		// map will be deterministic.

		TreeMap<String, JarEntry> byName = new TreeMap<String, JarEntry>();

		for (Enumeration<JarEntry> e = jar.entries(); e.hasMoreElements(); ) {
			JarEntry entry = e.nextElement();
			byName.put(entry.getName(), entry);
		}

		for (JarEntry entry : byName.values()) {
			String name = entry.getName();
			if (!entry.isDirectory() && !name.equals(JarFile.MANIFEST_NAME)
					&& !name.equals(CERT_SF_NAME) && !name.equals(CERT_RSA_NAME)
					&& !name.equals(OTACERT_NAME)
					&& (stripPattern == null || !stripPattern.matcher(name).matches())) {
				InputStream data = jar.getInputStream(entry);
				while ((num = data.read(buffer)) > 0) {
					md.update(buffer, 0, num);
				}

				Attributes attr = null;
				if (input != null)
					attr = input.getAttributes(name);
				attr = attr != null ? new Attributes(attr) : new Attributes();
				attr.putValue("SHA1-Digest", base64.encode(md.digest()));
				output.getEntries().put(name, attr);
			}
		}

		return output;
	}

	/** Write to another stream and also feed it to the Signature object. */
	private static class SignatureOutputStream extends FilterOutputStream {
		private Signature mSignature;
		private int mCount;

		public SignatureOutputStream(OutputStream out, Signature sig) {
			super(out);
			mSignature = sig;
			mCount = 0;
		}

		@Override
		public void write(int b) throws IOException {
			try {
				mSignature.update((byte) b);
			} catch (SignatureException e) {
				throw new IOException("SignatureException: " + e);
			}
			super.write(b);
			mCount++;
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			try {
				mSignature.update(b, off, len);
			} catch (SignatureException e) {
				throw new IOException("SignatureException: " + e);
			}
			super.write(b, off, len);
			mCount += len;
		}

		public int size() {
			return mCount;
		}
	}

	/** Write a .SF file with a digest of the specified manifest. */
	private static void writeSignatureFile(Manifest manifest,
			SignatureOutputStream out) throws IOException, GeneralSecurityException {
		Manifest sf = new Manifest();
		Attributes main = sf.getMainAttributes();
		main.putValue("Signature-Version", "1.0");

		BASE64Encoder base64 = new BASE64Encoder();
		MessageDigest md = MessageDigest.getInstance("SHA1");
		PrintStream print = new PrintStream(new DigestOutputStream(
				new ByteArrayOutputStream(), md), true, "UTF-8");

		// Digest of the entire manifest
		manifest.write(print);
		print.flush();
		main.putValue("SHA1-Digest-Manifest", base64.encode(md.digest()));

		Map<String, Attributes> entries = manifest.getEntries();
		for (Map.Entry<String, Attributes> entry : entries.entrySet()) {
			// Digest of the manifest stanza for this entry.
			print.print("Name: " + entry.getKey() + "\r\n");
			for (Map.Entry<Object, Object> att : entry.getValue().entrySet()) {
				print.print(att.getKey() + ": " + att.getValue() + "\r\n");
			}
			print.print("\r\n");
			print.flush();

			Attributes sfAttr = new Attributes();
			sfAttr.putValue("SHA1-Digest", base64.encode(md.digest()));
			sf.getEntries().put(entry.getKey(), sfAttr);
		}

		sf.write(out);

		// A bug in the java.util.jar implementation of Android platforms
		// up to version 1.6 will cause a spurious IOException to be thrown
		// if the length of the signature file is a multiple of 1024 bytes.
		// As a workaround, add an extra CRLF in this case.
		if ((out.size() % 1024) == 0) {
			out.write('\r');
			out.write('\n');
		}
	}

	/** Write a .RSA file with a digital signature. */
	private static void writeSignatureBlock(Signature signature,
			X509Certificate publicKey, OutputStream out) throws IOException,
			GeneralSecurityException {
		SignerInfo signerInfo = new SignerInfo(new X500Name(publicKey
				.getIssuerX500Principal().getName()), publicKey.getSerialNumber(),
				AlgorithmId.get("SHA1"), AlgorithmId.get("RSA"), signature.sign());

		PKCS7 pkcs7 = new PKCS7(new AlgorithmId[] { AlgorithmId.get("SHA1") },
				new ContentInfo(ContentInfo.DATA_OID, null),
				new X509Certificate[] { publicKey }, new SignerInfo[] { signerInfo });

		pkcs7.encodeSignedData(out);
	}

	/**
	 * Copy all the files in a manifest from input to output. We set the
	 * modification times in the output to a fixed time, so as to reduce variation
	 * in the output file and make incremental OTAs more efficient.
	 */
	private static void copyFiles(Manifest manifest, JarFile in,
			JarOutputStream out, long timestamp) throws IOException {
		byte[] buffer = new byte[4096];
		int num;

		Map<String, Attributes> entries = manifest.getEntries();
		List<String> names = new ArrayList<>(entries.keySet());
		Collections.sort(names);
		for (String name : names) {
			JarEntry inEntry = in.getJarEntry(name);
			JarEntry outEntry;
			if (inEntry.getMethod() == JarEntry.STORED) {
				// Preserve the STORED method of the input entry.
				outEntry = new JarEntry(inEntry);
			} else {
				// Create a new entry so that the compressed len is recomputed.
				outEntry = new JarEntry(name);
			}
			outEntry.setTime(timestamp);
			out.putNextEntry(outEntry);

			InputStream data = in.getInputStream(inEntry);
			while ((num = data.read(buffer)) > 0) {
				out.write(buffer, 0, num);
			}
			out.flush();
		}
	}

	/**
	 * Invokes file.delete() and if that fails, file.deleteOnExit(). Immediately
	 * returns if file is null.
	 **/
	public static void delete(final File file) {
		if (file == null) {
			return;
		}

		if (!file.delete()) {
			file.deleteOnExit();
		}
	}

	// Public key.
	private static final byte[] publicBytes = IOUtils.toByteArray(Sign.class
			.getResourceAsStream("/testkey.x509.pem"));
	// Private key.
	private static final byte[] privateBytes = IOUtils.toByteArray(Sign.class
			.getResourceAsStream("/testkey.pk8"));

	// Only compile the pattern once.
	private static Pattern endApk = Pattern.compile("\\.apk$");

	public static void sign(String inputApkPath, boolean override) throws IOException {
		String outputApkPath = endApk.matcher(inputApkPath).replaceAll("")
				+ ".s.apk";

		final File input = new File(inputApkPath);

		if (!input.exists() || !input.isFile()) {
			throw new RuntimeException("Input is not an existing file. " + inputApkPath);
		}

		File renamedInput = null;

		if (override) {
			outputApkPath = inputApkPath;

			renamedInput = new File(input.getParentFile(),
					new Date().getTime() + ".tmp");

			if (!input.renameTo(renamedInput)) {
				throw new RuntimeException("Unable to rename input apk. "
						+ inputApkPath);
			}

			inputApkPath = renamedInput.getAbsolutePath();
		}

		try (JarFile inputJar = new JarFile(new File(inputApkPath), false);
				JarOutputStream outputJar = new JarOutputStream(new FileOutputStream(new File(outputApkPath)))) {
			X509Certificate publicKey = readPublicKey();

			// Assume the certificate is valid for at least an hour.
			long timestamp = publicKey.getNotBefore().getTime() + 3600L * 1000;

			PrivateKey privateKey = readPrivateKey();

			outputJar.setLevel(9);

			Manifest manifest = addDigestsToManifest(inputJar);

			// Everything else
			copyFiles(manifest, inputJar, outputJar, timestamp);

			// MANIFEST.MF
			JarEntry je = new JarEntry(JarFile.MANIFEST_NAME);
			je.setTime(timestamp);
			outputJar.putNextEntry(je);
			manifest.write(outputJar);

			// CERT.SF
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKey);
			je = new JarEntry(CERT_SF_NAME);
			je.setTime(timestamp);
			outputJar.putNextEntry(je);
			writeSignatureFile(manifest, new SignatureOutputStream(outputJar,
					signature));

			// CERT.RSA
			je = new JarEntry(CERT_RSA_NAME);
			je.setTime(timestamp);
			outputJar.putNextEntry(je);
			writeSignatureBlock(signature, publicKey, outputJar);
		} catch (Exception e) {
			throw new IOException("Unexpected condition", e);
		} finally {
			if (renamedInput != null) {
				delete(renamedInput);
			}
		}
	}
}