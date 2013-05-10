package net.jalg.hawkj;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import net.jalg.hawkj.WwwAuthenticateHeader.WwwAuthenticateBuilder;
import net.jalg.hawkj.util.Base64;

/**
 * HawkWwwAuthenticateContext is an immutable class for working with Hawk 401
 * Unauthorized responses.
 * 
 * HawkWwwAuthenticateContext instances contain
 * <ul>
 * <li>A timestamp to inform client about the server's current time</li>
 * <li>Credentials: id, key, and algorithm to calculate the timestamp HMAC</li>
 * </ul>
 * <p>
 * HawkWwwAuthenticateContext instances are created using a fluent API that uses
 * a set of interfaces and {@link HawkWwwAuthenticateContextBuilder}) to guide
 * the user through the process of supplying the necessary data at each step.
 * The process follows these general steps:
 * <p>
 * For creating timestamp reponses:
 * <ol>
 * <li>Use builder method ts() to create context with new current timestamp or
 * supply timestamp and its HMAC directly when parsing an incoming
 * WWW-Authenticate header.</li>
 * <li>Provide credentials for HMAC creation and checking.</li>
 * <li></li>
 * </ol>
 * Given an instance of the HawkWwwAuthenticateContext class, the API is
 * designed to enable tasks such as
 * <ul>
 * <li>Create a WWW-Authenticate header value</li>
 * <li>Validate a received timestamp HMAC</li>
 * </ul>
 * 
 * @author Jan Algermissen, http://jalg.net
 * 
 */
public class HawkWwwAuthenticateContext {

	public static final String SCHEME = "Hawk";
	private static final String SLF = "\n"; // String-LineFeed
	private static final String HAWK_VERSION = "1";
	private static final String HAWK_TS_PREFIX = "hawk." + HAWK_VERSION + ".ts";

	private final int ts;
	private final String tsm;

	private final String id;
	private final String key;
	private final Algorithm algorithm;

	private HawkWwwAuthenticateContext() {
		this.ts = 0;
		this.tsm = null;
		this.id = null;
		this.key = null;
		this.algorithm = null;

	}

	private HawkWwwAuthenticateContext(int ts, String tsm, String id,
			String key, Algorithm algorithm) {
		this.ts = ts;
		this.tsm = tsm;
		this.id = id;
		this.key = key;
		this.algorithm = algorithm;

	}

	public int getTs() {
		return this.ts;
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

	public String getTsm() {
		return this.tsm;
	}

	public boolean hasTs() {
		return ts != 0;
	}

	public boolean hasTsm() {
		return tsm != null;
	}

	/**
	 * Create a WWW-Authenticate header from this HawkWwwAuthenticateContext.
	 * 
	 * The method returns a new WwwAuthenticateHeader instance from the data
	 * contained in this HawkWwwAuthenticateContext.
	 * <p>
	 * If the context has a timestamp but no timestamp HMAC, a new HMAC for the
	 * timestamp is created using the supplied credentials.
	 * 
	 * @see net.jalg.hawkj.WwwAuthenticateHeader
	 * 
	 * @return The newly created header object.
	 * @throws HawkException
	 */
	public WwwAuthenticateHeader createWwwAuthenticateHeader()
			throws HawkException {

		WwwAuthenticateBuilder headerBuilder = WwwAuthenticateHeader
				.wwwAuthenticate();

		if (hasTs()) {
			if (!hasTsm()) {
				String hmac = this.generateHmac();
				headerBuilder.ts(getTs()).tsm(hmac);
			} else {
				headerBuilder.ts(getTs()).tsm(getTsm());

			}
		}

		return headerBuilder.build();
	}

	/**
	 * Check whether a given HMAC value matches the HMAC for the timestamp in
	 * this HawkWwwAuthenticateContext.
	 * 
	 * @param hmac
	 *            The HMAC value to test.
	 * @return true if the HMAC matches the HMAC computed for this context,
	 *         false otherwise.
	 * @throws HawkException
	 */
	public boolean isValidTimestampMac(String hmac) throws HawkException {
		String this_hmac = this.generateHmac();
		return Util.fixedTimeEqual(this_hmac, hmac);
	}

	/**
	 * Generate base string for timestamp HMAC generation.
	 * 
	 * @return
	 */
	private String getBaseString() {
		if (!hasTs()) {
			throw new IllegalStateException(
					"This HawkWwwAuthenticateContext has no timestamp");
		}
		return new StringBuilder(HAWK_TS_PREFIX).append(SLF).append(getTs())
				.append(SLF).toString();
	}

	@Override
	public String toString() {
		return "HawkWwwAuthenticateContext [ts=" + ts + ", tsm=" + tsm
				+ ", id=" + id + ", key=xxxx, algorithm=" + algorithm + "]";
	}

	/**
	 * Generate an HMAC from the context ts parameter.
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

		SecretKeySpec secret_key = new SecretKeySpec(getKey().getBytes(
				StandardCharsets.UTF_8), getAlgorithm().getMacName());
		try {
			mac.init(secret_key);
		} catch (InvalidKeyException e) {
			throw new HawkException("Key is invalid ", e);
		}

		return new String(Base64.encodeBase64(mac.doFinal(baseString
				.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);
	}

	/**
	 * Create a new HawkWwwAuthenticateContextBuilder_A, initialized with
	 * timestamp and timestamp hmac.
	 * 
	 * @param ts
	 *            The timestamp
	 * @param tsm
	 *            The timestamp HMAC
	 * @return A new Builder with the parameters set.
	 */
	public static HawkWwwAuthenticateContextBuilder_A tsAndTsm(int ts,
			String tsm) {
		return new HawkWwwAuthenticateContextBuilder().ts(ts).tsm(tsm);
	}

	public static HawkWwwAuthenticateContextBuilder_A ts() {
		int now = (int) (System.currentTimeMillis() / 1000L);
		return new HawkWwwAuthenticateContextBuilder().ts(now);
	}

	public static interface HawkWwwAuthenticateContextBuilder_A {
		public HawkWwwAuthenticateContextBuilder credentials(String id,
				String key, Algorithm algorithm);
	}

	/**
	 * @author Jan Algermissen, http://jalg.net
	 * 
	 */
	public static class HawkWwwAuthenticateContextBuilder implements
			HawkWwwAuthenticateContextBuilder_A {

		private String id;
		private String key;
		private Algorithm algorithm;

		private int ts;
		private String tsm;

		private HawkWwwAuthenticateContextBuilder() {
		}

		private HawkWwwAuthenticateContextBuilder ts(int ts) {
			if (ts <= 0) {
				throw new IllegalArgumentException("0 is an invalid timestamp");
			}
			this.ts = ts;
			return this;
		}

		private HawkWwwAuthenticateContextBuilder tsm(String tsm) {
			if (tsm == null || tsm.length() == 0) {
				throw new IllegalArgumentException("Null or empty tsm not allowed");
			}
			this.tsm = tsm;
			return this;
		}

		private HawkWwwAuthenticateContextBuilder id(String id) {
			if (id == null || id.length() == 0) {
				throw new IllegalArgumentException("Null or empty id not allowed");
			}
			this.id = id;
			return this;
		}

		private HawkWwwAuthenticateContextBuilder key(String key) {
			if (key == null || key.length() == 0) {
				throw new IllegalArgumentException("Null or empty key not allowed");
			}
			this.key = key;
			return this;
		}

		private HawkWwwAuthenticateContextBuilder algorithm(Algorithm algorithm) {
			if (algorithm == null) {
				throw new IllegalArgumentException("Null algorithm not allowed");
			}
			this.algorithm = algorithm;
			return this;
		}

		public HawkWwwAuthenticateContextBuilder credentials(String id,
				String key, Algorithm algorithm) {
			return id(id).key(key).algorithm(algorithm);
		}

		public HawkWwwAuthenticateContext build() throws HawkException {

			/*
			 * If this is a builder for/from a header that has a ts-parameter...
			 * (tsm can be set (when parsed from header) or null, in which case
			 * it will be generated when a header is built from us.
			 */
			if (this.ts != 0) {
				/*
				 * Since we do mac-ing of the timestamp, when generating for
				 * header or when validating from header with us, we need
				 * credentials in the context.
				 */
				if (this.id == null || this.key == null
						|| this.algorithm == null) {
					throw new IllegalStateException("Null or empty key not allowed");
				}
				/*
				 * Create a new context for WWW-Authenticate headers that
				 * communicate a current timestamp to the client.
				 */
				return new HawkWwwAuthenticateContext(this.ts, this.tsm,
						this.id, this.key, this.algorithm);

			}

			/*
			 * Sometimes we do have an empty builder, because just 'Hawk' is a
			 * valid WWW-Authenticate header value for Hawk 401 responses.
			 */
			return new HawkWwwAuthenticateContext();
		}

	}

}
