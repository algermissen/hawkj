package net.jalg.hawkj;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import net.jalg.hawkj.AuthorizationHeader.AuthorizationBuilder;
import net.jalg.hawkj.util.Base64;

/**
 * HawkContext is an immutable class for working with Hawk authentication data.
 * 
 * HawkContext instances contain
 * <ul>
 * <li>HTTP request data: method, path, host, and port.</li>
 * <li>Replay protection data: timestamp and nonce.</li>
 * <li>Credentials: id, key, and algorithm.</li>
 * <li>Payload hash: a hash of request or response payload.</li>
 * <li>Extension data: application specific extension data.</li>
 * </ul>
 * <p>
 * HawkContext instances are created using a fluent API that uses a set of
 * interfaces (HawkContextBuilder_A, HawkContextBuilder_B, HawkContextBuilder_C,
 * and {@link HawkContextBuilder}) to guide the user through the process of
 * supplying the necessary data at each step. The process follows these general
 * steps:
 * <ol>
 * <li>Provide request data.</li>
 * <li>Provide credentials.</li>
 * <li>Optionally provide timestamp and nonce. If they are not provided, they
 * will be generated by the builder's {@link HawkContextBuilder.build()} method
 * when the target instance is created.</li>
 * <li>Optionally provide a payload and content type. If these are provided, the
 * builder will generate the hash value according to <a
 * href="https://github.com/hueniverse/hawk#payload-validation">Hawk</a> and add
 * the hash value to the target instance during building.</li>
 * <li>Optionally (and <b>alternatively</b> to payload and content type) provide
 * a payload hash value. This value will be copied to the target instance during
 * the building process.</li>
 * <li>Optionally supply application specific extension data.</li>
 * <li></li>
 * </ol>
 * Given an instance of the HawkContext class, the API is designed to enable
 * tasks such as
 * <ul>
 * <li>Create a (Server-)Authorization header value</li>
 * <li>Validate a received HMAC</li>
 * <li>Validate a received body hash</li>
 * <li>Pass request and credentials information from a request handling chain to
 * the associated response handling chain.</li>
 * <li>Clone the instance to create a new builder. (Useful for creating response
 * HawkContext instance from a request HawkContext instance for generating a
 * Server-Authorization response header)</li>
 * </ul>
 * 
 * @author Jan Algermissen, http://jalg.net
 * 
 */
public class HawkContext {

	public static final String SCHEME = "Hawk";
	public static final String SERVER_AUTHORIZATION = "Server-Authorization";

	// private static final String BODY_HASH_ALGORITHM = "SHA-1";
	private static final String SLF = "\n"; // String-LineFeed
	private static final byte[] BLF = { '\n' }; // Byte-LineFeed

	private static final String HAWK_VERSION = "1";
	private static final String HAWK_HEADER_PREFIX = "hawk." + HAWK_VERSION
			+ ".header";
	private static final String HAWK_PAYLOAD_PREFIX = "hawk." + HAWK_VERSION
			+ ".payload";

	private final String method;
	private final String path;
	private final String host;
	private final int port;

	private final int ts;
	private final String nonce;

	private final String id;
	private final String key;
	private final Algorithm algorithm;

	private final String hash;

	private final String ext;

	private HawkContext(String method, String path, String host, int port,
			int ts, String nonce, String id, String key, Algorithm algorithm,
			String hash, String ext) {
		this.method = method;
		this.path = path;
		this.host = host;
		this.port = port;
		this.ts = ts;
		this.nonce = nonce;
		this.id = id;
		this.key = key;
		this.algorithm = algorithm;
		this.hash = hash;
		this.ext = ext;

	}

	public int getTs() {
		return this.ts;
	}

	public String getNonce() {
		return this.nonce;
	}

	public String getId() {
		return this.id;
	}

	public String getKey() {
		return this.key;
	}

	public Algorithm getAlgorithm() {
		return this.algorithm;
	}

	public String getMethod() {
		return this.method;
	}

	public String getPath() {
		return this.path;
	}

	public String getHost() {
		return this.host;
	}

	public int getPort() {
		return this.port;
	}

	public String getHash() {
		return this.hash;
	}

	public String getExt() {
		return this.ext;
	}

	public boolean hasHash() {
		return hash != null;
	}

	public boolean hasExt() {
		return ext != null;
	}

	/**
	 * Create an Authorization header from this HawkContext.
	 * 
	 * The method returns a new AuthorizationHeader instance from the data in
	 * this HawkContext. For this the HMAC of the contained data is calculated
	 * and put into the header with the other parameters required by the
	 * specification.
	 * 
	 * 
	 * @see net.jalg.hawkj.AuthorizationHeader
	 * 
	 * @return The newly created header object.
	 * @throws HawkException
	 */
	public AuthorizationHeader createAuthorizationHeader() throws HawkException {

		String hmac = this.generateHmac();

		AuthorizationBuilder headerBuilder = AuthorizationHeader
				.authorization().ts(ts).nonce(nonce).id(getId()).mac(hmac);
		if (hasExt()) {
			headerBuilder.ext(getExt());
		}
		if (hasHash()) {
			headerBuilder.hash(getHash());
		}

		return headerBuilder.build();
	}

	/**
	 * Verify that a given header matches a HawkContext.
	 * 
	 * This is designed to be used in clients in order to check the incoming
	 * Server-Authorization header.
	 * 
	 * @param header
	 *            The header (usually Server-Authorization)
	 * @return true if the header has the exact same id, ts and nonce.
	 */
	public boolean verifyServerAuthorizationMatches(AuthorizationHeader header) {
		if (!Util.fixedTimeEqual(header.getId(), this.getId())) {
			return false;
		}
		if (header.getTs() != this.getTs()) {
			return false;
		}
		if (!Util.fixedTimeEqual(header.getNonce(), this.getNonce())) {
			return false;
		}

		return true;
	}

	/**
	 * Check whether a given HMAC value matches the HMAC for this HawkContext.
	 * 
	 * @param hmac
	 *            The HMAC value to test.
	 * @return true if the HMAC matches the HMAC computed for this context,
	 *         false otherwise.
	 * @throws HawkException
	 */
	public boolean isValidMac(String hmac) throws HawkException {
		String this_hmac = this.generateHmac();
		return Util.fixedTimeEqual(this_hmac, hmac);
	}

	@Override
	public String toString() {
		return "Hawk [method=" + method + ", path=" + path + ", host=" + host
				+ ", port=" + port + ", ts=" + ts + ", nonce=" + nonce
				+ ", id=" + id + ", key=xxxx, algorithm=" + algorithm
				+ ", hash=" + hash + ", ext=" + ext + "]";
	}

	/**
	 * Generate base string for HMAC generation.
	 * 
	 * @return
	 */
	protected String getBaseString() {
		StringBuilder sb = new StringBuilder(HAWK_HEADER_PREFIX).append(SLF);
		sb.append(getTs()).append(SLF);
		sb.append(getNonce()).append(SLF);
		sb.append(getMethod()).append(SLF);
		sb.append(getPath()).append(SLF);
		sb.append(getHost()).append(SLF);
		sb.append(getPort()).append(SLF);
		sb.append(hasHash() ? getHash() : "").append(SLF);
		sb.append(hasExt() ? getExt() : "").append(SLF);
		// FIXME: escaping of stuff in ext to ha single ine.
		return sb.toString();

		// FIXME - this is a todo!
		// if (options.ext) {
		// normalized += options.ext.replace('\\', '\\\\').replace('\n', '\\n');
		// }
		//
		// normalized += '\n';
		//
		//
		// escapeHeaderAttribute: function (attribute) {
		//
		// return attribute.replace(/\\/g, '\\\\').replace(/\"/g, '\\"');
		// },
	}

	/**
	 * Generate an HMAC from the HawkContext.
	 * 
	 * @return
	 * @throws HawkException
	 */
	private String generateHmac() throws HawkException {

		String baseString = getBaseString();

		Mac mac;
		try {
			mac = Mac.getInstance(getAlgorithm().getMacName());
		} catch (NoSuchAlgorithmException e) {
			throw new HawkException("Unknown algorithm "
					+ getAlgorithm().getMacName(), e);
		}

		SecretKeySpec secretKey = new SecretKeySpec(getKey().getBytes(
				StandardCharsets.UTF_8), getAlgorithm().getMacName());

		try {
			mac.init(secretKey);
		} catch (InvalidKeyException e) {
			throw new HawkException("Key is invalid ", e);
		}

		return new String(Base64.encodeBase64(mac.doFinal(baseString
				.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);
	}

	/**
	 * Create a new HawkContextBuilder_C object from this HawkContext that has
	 * request data, credentials, and ts and nonce already set.
	 * <p>
	 * This method is designed to be used for generating Server-Authorization
	 * headers from HawkContexts parsed from Authorization headers.
	 * 
	 * @return HawkContextBuilder initialized with cloned data from this
	 *         HawkContext.
	 */
	public HawkContextBuilder_C cloneC() {
		return request(this.method, this.path, this.host, this.port)
				.credentials(this.id, this.key, this.algorithm).tsAndNonce(
						this.ts, this.nonce);
	}

	/**
	 * Create a new RequestBuilder_A, initialized with request data.
	 * 
	 * @param method
	 * @param path
	 * @param host
	 * @param port
	 * @return
	 */
	public static HawkContextBuilder_A request(String method, String path,
			String host, int port) {
		return new HawkContextBuilder().method(method).path(path).host(host)
				.port(port);
	}

	/**
	 * @author Jan Algermissen, http://jalg.net
	 * 
	 */
	public static interface HawkContextBuilder_A {
		public HawkContextBuilder_B credentials(String id, String key,
				Algorithm algorithm);
	}

	/**
	 * @author Jan Algermissen, http://jalg.net
	 * 
	 */
	public static interface HawkContextBuilder_B {
		public HawkContextBuilder_C tsAndNonce(int ts, String nonce);

		public HawkContextBuilder_C body(byte[] body, String contentType);

		public HawkContextBuilder_C hash(String hash);

		public HawkContextBuilder_C ext(String ext);

		public HawkContext build() throws HawkException;
	}

	/**
	 * @author Jan Algermissen, http://jalg.net
	 * 
	 */
	public static interface HawkContextBuilder_C {
		public HawkContextBuilder_C body(byte[] body, String contentType);

		public HawkContextBuilder_C hash(String hash);

		public HawkContextBuilder_C ext(String ext);

		public HawkContext build() throws HawkException;
	}

	/**
	 * @author Jan Algermissen, http://jalg.net
	 * 
	 */
	public static class HawkContextBuilder implements HawkContextBuilder_A,
			HawkContextBuilder_B, HawkContextBuilder_C {

		private String method;
		private String path;
		private String host;
		private int port;
		private byte[] body;
		private String hash;

		private String id;
		private String key;

		private int ts;
		private String nonce;

		private String ext;

		private Algorithm algorithm;
		private String contentType;

		private HawkContextBuilder() {
		}

		private HawkContextBuilder method(String method) {
			if (method == null || method.length() == 0) {
				throw new IllegalArgumentException("Null or empty method not allowed");
			}
			this.method = method;
			return this;
		}

		private HawkContextBuilder path(String path) {
			if (path == null || path.length() == 0) {
				throw new IllegalArgumentException("Null or empty path not allowed");
			}
			this.path = path;
			return this;
		}

		private HawkContextBuilder host(String host) {
			if (host == null || host.length() == 0) {
				throw new IllegalArgumentException("Null or empty not allowed");
			}
			this.host = host;
			return this;
		}

		private HawkContextBuilder port(int port) {
			if (port <= 0) {
				throw new IllegalArgumentException("0 is an invalid port number");
			}
			this.port = port;
			return this;
		}

		private HawkContextBuilder ts(int ts) {
			if (ts <= 0) {
				throw new IllegalArgumentException("0 is an invalid time stamp");
			}
			this.ts = ts;
			return this;
		}

		private HawkContextBuilder nonce(String nonce) {
			if (nonce == null || nonce.length() == 0) {
				throw new IllegalArgumentException("Null or empty nonce not allowed");
			}
			this.nonce = nonce;
			return this;
		}

		private HawkContextBuilder id(String id) {
			if (id == null || id.length() == 0) {
				throw new IllegalArgumentException("Null or empty id not allowed");
			}
			this.id = id;
			return this;
		}

		private HawkContextBuilder key(String key) {
			if (key == null || key.length() == 0) {
				throw new IllegalArgumentException("Null or empty key not allowed");
			}
			this.key = key;
			return this;
		}

		private HawkContextBuilder algorithm(Algorithm algorithm) {
			if (algorithm == null) {
				throw new IllegalArgumentException("Null algorithm is not allowed");
			}
			this.algorithm = algorithm;
			return this;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * net.jalg.hawkj.HawkContext.HawkContextBuilder_A#credentials(java.
		 * lang.String, java.lang.String, net.jalg.hawkj.Algorithm)
		 */
		public HawkContextBuilder_B credentials(String id, String key,
				Algorithm algorithm) {
			return id(id).key(key).algorithm(algorithm);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see net.jalg.hawkj.HawkContext.HawkContextBuilder_B#tsAndNonce(int,
		 * java.lang.String)
		 */
		public HawkContextBuilder_C tsAndNonce(int ts, String nonce) {
			return ts(ts).nonce(nonce);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see net.jalg.hawkj.HawkContext.HawkContextBuilder_B#body(byte[],
		 * java.lang.String)
		 */
		public HawkContextBuilder_C body(byte[] body, String contentType) {
			if (body == null || body.length == 0) {
				throw new IllegalArgumentException(
						"Body must not be null or empty");
			}
			// empty content type is ok according to Hawk.
			if (contentType == null) { 
				throw new IllegalArgumentException(
						"Content type must not be null");
			}
			this.body = body;
			this.contentType = contentType;
			return this;
		}

		// FIXME: Document that null or empty is allowed but has no effect
		// in order to avoid interrupting fluid interface with 'if's
		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * net.jalg.hawkj.HawkContext.HawkContextBuilder_B#hash(java.lang.String
		 * )
		 */
		public HawkContextBuilder_C hash(String hash) {
			if (hash != null && hash.length() > 0) {
				this.hash = hash;
			}
			return this;
		}

		// FIXME: Document that null or empty is allowed but has no effect
		// in order to avoid interrupting fluid interface with 'if's
		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * net.jalg.hawkj.HawkContext.HawkContextBuilder_B#ext(java.lang.String)
		 */
		public HawkContextBuilder_C ext(String ext) {
			if (ext == null || ext.length() == 0) {
				return this;
			}
			if (ext.contains("\"")) {
				throw new IllegalArgumentException(
						"Double quotes in ext-data are currently not handled by hawkj");
			}
			if (ext.contains("\n")) {
				throw new IllegalArgumentException(
						"Line feeds in ext-data are currently not handled by hawkj");
			}
			if (ext.contains("\\")) {
				throw new IllegalArgumentException(
						"Escaped characters in ext-data are currently not handled by hawkj");
			}
			this.ext = ext;
			return this;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see net.jalg.hawkj.Jhawk.B#build()
		 */
		public HawkContext build() throws HawkException {

			int ts = 0;
			String nonce = null;
			String hash = null;

			/*
			 * If ts has not been provided it means that we should generate a
			 * new timestamp.
			 */
			if (this.ts == 0) {
				ts = (int) (System.currentTimeMillis() / 1000);
			} else {
				ts = this.ts;
			}

			/*
			 * If nonce has not been provided it means that we should generate a
			 * new nonce.
			 */
			if (this.nonce == null) {
				nonce = Util.generateRandomString(6); // FIXME: Why 6? results
														// in 12 due to
														// bytesToHex. FIXME!
			} else {
				nonce = this.nonce;
			}

			/*
			 * Handle body and alternatively hash values. Generate hash if have
			 * body.
			 */
			if (this.body != null && this.body.length > 0) {
				if (this.hash != null) {
					throw new IllegalStateException(
							"Cannot have body and hash, only either one");
				}
				hash = HawkContextBuilder.generateHash(this.algorithm,
						this.body, this.contentType);
			} else {
				if (!(this.hash == null || this.hash.trim().equals(""))) {
					hash = this.hash;
				}
			}

			return new HawkContext(this.method, this.path, this.host,
					this.port, ts, nonce, this.id, this.key, this.algorithm,
					hash, this.ext);
		}

		/**
		 * Calculate payload hash.
		 * 
		 * @param body
		 * @param contentType
		 * @return
		 * @throws HawkException
		 */
		public static String generateHash(Algorithm algorithm, byte[] body,
				String contentType) throws HawkException {

			if (body == null || body.length == 0) {
				throw new IllegalArgumentException(
						"Body must not be null or empty");
			}

			if (contentType == null) {
				throw new IllegalArgumentException(
						"Content type must not be null or empty");
			}
			/*
			 * Strip any parameters from media type. (If we have no match, first
			 * element will be original) E.g. from 'application/atom;type=feed'
			 * make 'application/atom'.
			 */
			String ct = contentType.split(";")[0].trim();

			String baseString = new StringBuilder(HAWK_PAYLOAD_PREFIX)
					.append(SLF).append(ct).append(SLF).toString();

			try {
				MessageDigest md = MessageDigest.getInstance(algorithm
						.getMessageDigestName());
				
				md.update(baseString.getBytes(StandardCharsets.UTF_8));
				md.update(body);
				md.update(BLF);
				return new String(Base64.encodeBase64(md.digest()),
						StandardCharsets.UTF_8);
			} catch (NoSuchAlgorithmException e1) {
				throw new HawkException("Digest algorithm "
						+ algorithm.getMessageDigestName() + " not found", e1);
			}

		}

	}

}
