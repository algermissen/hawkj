package net.jalg.hawkj;

/** A builder that is called by an auth-header parse.
 * 
 * Users of the parser API have to supply an implementation of this interface.
 * 
 * @author Jan Algermissen, http://jalg.net
 *
 */
public interface AuthDirectiveBuilder {

	/** Callback to be called when the authentication scheme name is parsed.
	 * @param scheme
	 * @throws AuthHeaderParsingException
	 */
	public void scheme(String scheme) throws AuthHeaderParsingException;
	
	/** Callback to be called when a token86 header field is parsed.
	 * 
	 * The parser ensures that this method will only be called once. Should the parser encounter more than
	 * one token68 field in a given header value it will abort the parsing and report an error.
	 * 
	 * @param token
	 * @throws AuthHeaderParsingException
	 */
	public void token(String token) throws AuthHeaderParsingException;

	/** Callback to be called when a name-value field has been parsed.
	 * 
	 * The parser will remove any leading or trailing double quotation marks from the value and unescpae any
	 * escaped double quotation marks in the value.
	 * 
	 * @param key
	 * @param value
	 * @throws AuthHeaderParsingException
	 */
	public void param(String key, String value) throws AuthHeaderParsingException;

}
