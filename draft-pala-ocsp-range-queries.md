---
title: "Range Queries Extension for OCSP"
abbrev: "OCSP Range Queries"
docname: draft-pala-ocsp-range-queries-latest

ipr: trust200902
area: Security
cat: std

coding: utf-8
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author:
 -
    ins: M. Pala
    name: Massimiliano Pala
    org: OpenCA Labs
    city: New York City, New York
    country: United States of America
    email: director@openca.org

normative:
  RFC6960:
  RFC5280:

informative:


--- abstract

The Online Certificate Status Protocol (OCSP) provides single-certificate-revocation status in real-time. However, the per-certificate lookup approach employed in OCSP has performance and scalability issues when faced with large population of active certificates. This document describes a new extension and associated processing rules for OCSP message to support optimized range-based responses. Specifically, when requested by the client, the returned response is modified to cover a range of certificates with the same status, instead of only the one requested, thus correlating the number of signed responses to the population of revoked certificates instead of the active certificates one.

--- middle

# Introduction {#intro}

The original design for the OCSP protocol was based on a live responder model where each query would be replied to with a freshly signed new response that could be cached for the duration of the response which it was meant to be a short period of time such as few minutes to few hours. This model was meant to provide real-time revocation status for a single certificate. However, the per-certificate lookup approach employed in OCSP has proven to have performance and scalability issues. This is particularly true when the number of certificates issued by the specific CA is very large and requests for status verification are clustered around a subset of the certificates. In other words, the current design of the OCSP protocol [RFC6960] ties the number of possible responses that the OCSP responder must be able to produce is tied to the number of certificates issued, instead of the number of certificates revoked.

To overcome the issue with responders' performances, certificate providers pre-compute all responses for the active certificates population and serve quite long-lived responses from CDNs, which is very expensive and an evident barrier to revocation status checking.

## Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

The following terminology is used throughout this document:

**CLIENT**:
          A client application accessing the OCSP responder to query
          for the status of a certificate.

**RESPONDER**:
          A client application accessing the OCSP responder to query
          for the status of a certificate.

**OCSP**:
          Online Certificate Status Protocol, version 1.

**OCSP Extension**:
          X.509 extension for OCSP requests or responses.

**CRL**:
          Certificate Revocation List.

**CA**:
          Certificate Authority.

**DER**:
          Distinguished Encoding Rules as defined in X.690.

**PKI**:
          Public Key Infrastructure, as defined in [RFC5280].

# OCSP Range Queries {#range-queries}

The OCSP Range Queries extension allows OCSP responders to provide only a handful of responses, thus removing the need for large CDN deployments or the need of shortening the lifetime of certificates.

When the OCSP Range Query extension (i.e., `OCSPRangeQuery`) is provided in the OCSP request, the client indicates that they support range queries. In this case, if the responder does not provide support for range queries, the responder replies with a standard OCSP response that the client processes as usual.

However, when the responder supports range queries, the responder SHALL reply with an OCSP response that carries the `OCSPRangeResponse` extension that specifies the range of certificates for which the response is valid.

The serial number of the CertID is set to a well-know value that the client ignores when the `OCSPRangeResponse` extension is present in the response. The client will then use the `startCertID` and `endCertID` values to determine the range of certificates for which the response is valid.

The `startCertID` and `endCertID` values are the first and last certificate serial numbers for which the response is valid (inclusive). The minimum value for the `startCertID` is zero (0). If the `endCertID` is not present, the value to use for the end of the range is `+Infinite` (meaning the largest value supported).

## The OCSP Range Queries Extension {#range-queries-extension}

When an OCSP client supports OCSP range responses, the client MUST include the `OCSPRangeResponse` extension with the value set to `NULL`. OCSP clients that do not support range queries SHALL NOT include the `OCSPRangeResponse` extension. The extension is defined as follows:

~~~ ASN.1

   id-range-response OBJECT IDENTIFIER ::= { id-pkix-ocsp 10 }

   OCSPRangeResponse ::= NULL
~~~
{: #asn1-ocsp-range-response title="The OCSP Range Response Extension ASN.1 Definition"}

## The OCSPRange Extension {#ocsp-range}

When an OCSP client includes the `OCSPRangeResponse` extension in the OCSP request message, the responder MUST include the `OCSPRange` extension in the OCSP response message. The `OCSPRange` extension allows a responder to indicate the range of responses for which the response is valid. The extension is defined as follows:

~~~ ASN.1

   id-ocsp-range-response OBJECT IDENTIFIER ::= { id-pkix-ocsp 11 }

   OCSPRange ::= SEQUENCE {
       startCertID  [0]     INTEGER,
            --- Beginning of the range of certificates
            --- for which the response is valid. The
            --- lowest value is 0.

       endCertID    [1]     INTEGER OPTIONAL
            --- End of the range of certificates for
            --- which the response is valid. If the value
            --- is not present, the default value to use
            --- is +Infinite.
   }
~~~
{: #asn1-ocsp-range title="The OCSP Range Extension ASN.1 Definition"}

Where the `startCertID` and `endCertID` values are the first and last certificate serial numbers for which the response is valid (inclusive). If the `endCertID` is not present, the default value to use is +Infinite (meaning the largest value supported).

# OCSP Requests and Responses Processing {#sec-changes}

This section is meant to provide indications for implementers about how to properly process requests and responses that use the range queries extensions.

## Processing OCSP Requests {#sec-request}

When an OCSP client sends a request to an OCSP responder and includes the `OCSPRangeResponse` extension, the responder builds the response to bew sent to the client according to the following algorithm:

~~~
IF OCSPRangeResponse extension is present in the request THEN
    IF OCSPRangeResponse extension is supported by the responder THEN
        IF the requested serial number is not revoked THEN
            Include the OCSPRange extension in the response
            Set the startCertID and endCertID values in the OCSPRange extension
        ELSE
            Do not include the OCSPRange extension in the response
            Send the standard OCSP response for the revoked certificate
        END IF
    ELSE
        Send the standard OCSP response for the revoked certificate
    END IF
ELSE
    Send the standard OCSP response for the revoked certificate
END IF
~~~
{: #alg-ocsp-responder title="OCSP Responder Processing Algorithm"}

When a responder does not support the `OCSPRangeResponse` extension, the responder SHALL ignore it and respond with a standard OCSP response that the client processes as usual.

## Processing OCSP Responses {#sec-response}

When an OCSP client receives a response from an OCSP responder, the client processes the response according to the following algorithm:

~~~
IF OCSPRange extension is present in the response THEN

    1. Ignore the serial number used in the CertID and Use the startCertID
       and endCertID values in the OCSPRange extension to determine if the
       response is valid for the certificate in the request.

    2. Process the response as usual

ELSE
    1. Process the response as usual

END IF
~~~
{: #alg-ocsp-client title="OCSP Client Processing Algorithm"}

## Pre-Computation of OCSP Responses {#sec-precompute}

To optimize the performance of the OCSP responder, the responder MAY pre-compute the responses for the ranges of active certificates population (one for each revoked certificate or range of revoked certificates plus one for each of valid certificates).

For example, when the population of active certificates is 1,000,000 (1,000 of which are revoked), the responder, instead of pre-computing 1,000,000 responses, only pre-computes the responses for the ranges of certificates that share the same status (revoked or valid) according to the following algorithm:

~~~
# Load the current CRL
aCRL :== Load(CRL)

# Sort the CRL by certificate serial number {R0, ..., RN}
aCRL :== Sort(aCRL)

# Initialize the variables
aStatus :== VALID
aRangeStart :== 0
aRangeEnd :== 0
idx :== 0

# Process the CRL entries
FOREACH aEntry in the aCRL DO

    # Check the status of the current range
    IF aStatus == VALID THEN
        # We are in a range of valid certificates
        aRangeEnd :== aEntry - 1
        Responses(idx++) = Valid{aRangeStart, aRangeEnd}

        # Start for the next set of revoked certificates
        aRangeStart :== aRangeEnd :== aEntry.serial
        aStatus :== REVOKED

        # Skip to the next entry
        CONTINUE
    ELSE
        # The next entry is the next serial, we can extend the range
        IF aEntry.serial == aRangeEnd + 1 THEN
            # Extend the current range of revoked entries
            aRangeEnd++
            CONTINUE
        ELSE
            # Generate "REVOKED" response for the previouse range
            Responses(idx++)=Revoked{aRangeStart, aRangeEnd}

            # Sets the "VALID" response for the current range
            aRangeStart :== aRangeEnd + 1
            aRangeEnd :== aEntry.serial - 1
            Responses(idx++) :== Valid{aRangeStart, aRangeEnd}

            # Prepare for the next range of revoked entries
            aRangeStart :== aRangeEnd :== aEntry.serial
            aStatus :== REVOKED
        END IF
    END IF
~~~
{: #alg-precompute title="Algorithm for Pre-Computation of OCSP Responses"}

For example, for a CA with an active population of 10,000,000 certificates and a revoked population of 1,000 certificates, the responder will generate one response for the range of serial numbers from 0 to the first revoked certificate, one response for each range of certificates with the same status (revoked or valid), and one response for the range of serial numbers from the last revoked certificate to the largest serial number supported (i.e., +Infinite). In case all 1,000 revocation entries are not contiguous, the responder will generate 1,002 responses instead of 10,000,000 responses.

For high-performance OCSP responders, the pre-computation of responses for the ranges of certificates is a viable solution that can optimize the performances of responders: by reducing the number of responses that need to be generated, the responder can produce the responses in few seconds every few minutes/hours and directly serve them from memory or cache.

# Security Considerations {#sec-considerations}

The OCSP Range Queries extension does not introduce any new security considerations beyond those already present in the OCSP protocol.

# IANA Considerations {#iana-considerations}

This document has no IANA actions.


--- back

# ASN.1 Module

~~~ ASN.1

OCSPRangeResponseExtension-2009
    {iso(1) identified-organization(3) dod(6) internet(1) security(5)
    mechanisms(5) pkix(7) id-mod(0) id-mod-ocsp-range-response-2009(10)}

DEFINITIONS IMPLICIT TAGS ::=
BEGIN

-- EXPORTS All --

IMPORTS
    FROM PKIX1Explicit88 { iso(1) identified-organization(3) dod(6)
        internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
        id-pkix1-explicit-88(1) };

    id-pkix-ocsp OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
        dod(6) internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
        id-pkix1-explicit-88(1) 1 }

-- OCSP Range Response Extension

id-pkix-ocsp-range-response OBJECT IDENTIFIER ::= { id-pkix-ocsp 10 }
id-ocsp-range-response OBJECT IDENTIFIER ::= { id-pkix-ocsp 11 }

OCSPRangeResponse ::= NULL

OCSPRange ::= SEQUENCE {
    startCertID  [0]     INTEGER OPTIONAL,
                            --- Beginning of the range of certificates
                            --- for which the response is valid. If the
                            --- value is not present, the default value
                            --- to use is 0.

    endCertID    [1]     INTEGER OPTIONAL
                            --- End of the range of certificates for
                            --- which the response is valid. If the value
                            --- is not present, the default value to use
                            --- is +Infinite.
}

END
~~~

# Examples

TODO examples.

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

