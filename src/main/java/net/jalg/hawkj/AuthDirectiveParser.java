package net.jalg.hawkj;



/** A parser class for HTTP Authorization and WWW-Authenticate headers.
 * 
 * <b>Note</b>: This is at the moment only a very limited parser. See 'Open Issues' section in README.
 * 
 * @todo This class needs to become a real parser.
 * 
 * @author Jan Algermissen, http://jalg.net
 *
 */
public class AuthDirectiveParser {
	
	// FIXME add a 'have token flag' to enforce just one token68
	private AuthDirectiveBuilder builder;
	private String headerValue;
	
	public AuthDirectiveParser(String headerValue,AuthDirectiveBuilder builder) {
		this.builder = builder;
		if (headerValue == null) {
			throw new IllegalArgumentException("Unable to parse a null header value");
		}
		this.headerValue = headerValue;
	}
	
	// Note to self:
	// change implementation to work like this one:
	// http://javasourcecode.org/html/open-source/jdk/jdk-6u23/sun/net/www/protocol/http/AuthenticationHeader.java.html
	// http://javasourcecode.org/html/open-source/jdk/jdk-6u23/sun/net/www/HeaderParser.java.html

	
	public void parse() throws AuthHeaderParsingException {

		String[] parts = headerValue.trim().split("\\s+", 2);
		if (parts.length != 2) {
			throw new AuthHeaderParsingException("Unable to split scheme and other part in " + headerValue);
		}

		builder.scheme(parts[0]);
		
		// FIXME: handle optional, one-time token

		for (String kv : parts[1].split(",")) {
			String[] kva = kv.trim().split("=", 2);
			if (!(kva.length == 2)) {
				throw new AuthHeaderParsingException("Unable to split " + kv + " into parameter key and value in " + headerValue);
			}
			if (kva[1].startsWith("\"")) {
				kva[1] = kva[1].substring(1, kva[1].length() - 1);
			}
			builder.param(kva[0], kva[1]);
		}
	}

//	public String toHeaderValueString() {
//		StringBuilder sb = new StringBuilder(name);
//		boolean first = true;
//		if(token != null) {
//			sb.append(" ");
//			sb.append(token);
//			first = false;
//		}
//		for(String key : params.keySet()) {
//			if(first) {
//				sb.append(" ");
//				first = false;
//			} else {
//				sb.append(",");
//			}
//			sb.append(key);
//			sb.append("=\"");
//			sb.append(params.get(key));
//			sb.append("\"");
//			
//		}
//		return sb.toString();
//	}

}