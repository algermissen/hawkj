hawkj
=====

A Java implementation of Hawk

This is a Java implementation of the Hawk HTTP authentication scheme implemented by Eran Hammer's
[Hawk](https://github.com/hueniverse/hawk) node.js module.

Status
======

hawkj has been released as version 1.1 and is usable in production with the caveat
that no feedback from production is available so far. If you consider using hawkj
in production now, please get in touch.

The maven dependency is

    <dependency>
      <groupId>net.jalg</groupId>
      <artifactId>hawkj</artifactId>
      <version>1.2</version>
    </dependency>



Overview
========

hawkj essentially consists of two parts. On the one hand there is support for
parsing and creating HTTP Authorization, Server-Authorization (introduced by Hawk),
 and WWW-Authenticate headers.  On the
other hand hawkj provides the _HawkContext_ class which is used to manage the data
necessary to create and validate the information contained in these headers.

The HawkContext class is an immutable class that provides a fluent interface that
is intended to guide the user through the process of assembling the
required data in the correct way (meaning: help the user to get it right). 
In addition it encapsulates the mechanics of creating the HMAC signature
and the optional payload hash and provides some methods for verification
of HMACs and payload hashes received as art of (Server-)Authorize headers.

For additional information look at the [HawkContext class](https://github.com/algermissen/hawkj/blob/master/src/main/java/net/jalg/hawkj/HawkContext.java)


Example
=======

This is an example how to parse an incoming Authorization header in a JAX-RS 2.0
container request filter context:

    AuthorizationHeader authHeader = AuthorizationHeader.authorization(
                 requestContext.getHeaderString(HttpHeaders.AUTHORIZATION));

    // ...obtain id, password and algorithm using authHeader.getId()


And how to create a Hawk instance from that header:


    URI uri = requestContext.getUriInfo().getRequestUri();
    HawkContext hawk = HawkContext.request(requestContext.getMethod(), uri.getPath(),
                                           uri.getHost(), uri.getPort())
                         .credentials(id, password, algorithm)
                         .tsAndNonce(authHeader.getTs(), authHeader.getNonce())
                         .hash(authHeader.getHash()).build();

    /*
     * Now we use the created Hawk to validate the HMAC sent by the client
     * in the Authorization header.
     */
    if (!hawk.isValidMac(authHeader.getMac())) {
          LOG.log(Level.SEVERE, "Unable to validate HMAC signature");
          requestContext.abortWith(createDefault401Response());
          return;
    }



