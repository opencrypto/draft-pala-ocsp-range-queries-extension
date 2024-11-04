---
title: "OCSP Range Extension"
abbrev: "OCSP Range Responses"
docname: draft-pala-ocsp-range-responses-latest

ipr: trust200902
area: Security
cat: std
submissionType: IETF

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
  RFC2560:
  RFC5280:

informative:


--- abstract

The Online Certificate Status Protocol (OCSP) provides single-certificate-revocation status, originally designed to be provided in real-time. However, the per-certificate lookup approach employed in OCSP has performance and scalability issues when faced with large population of active certificates and clients.

This document describes a new extension and associated processing rules for OCSP messages that implement range-based responses. Specifically, the generated responses are modified to provide the status for a range of certificates, instead of a single one. The use of this extension fixes a long-standing design issue of OCSP, thus correlating the number of needed OCSP responses to the population of revoked certificates instead of the active certificates one.

--- middle

# Introduction and Motivation {#intro}

The trust model used in PKIs is based on two main components: the certificate chain and the certificate's revocation status. The revocation status is carried in lists of certificates that have been revoked by the Certificate Authority (CA) before their expiration date, namely the CRL. Alternatively, especially for EE certificates, the use of OCSP responders provides a more efficient mechanism that addresses the issue of growing CRLs. The first version of the OCSP protocol was defined in [RFC2560] and later updated in [RFC6960].

The original design of the OCSP protocol was based on a live responder model where each query is replied to with a freshly signed new response that could be cached for the duration of the response's validity period. OCSP responses were originally meant to be short-lived (e.g., few minutes to few hours).

This model has proven to have performance and scalability issues, especially for PKIs with large populations or for high-transactions systems. In fact, the current standard ties the number of responses to the number of issued certificates (i.e., one response for each valid certificates), instead of the number of revoked certificates.

To overcome the issue with responders' performances, it is a common practice for certificate providers to pre-compute all responses for the active certificates population and serve quite long-lived responses from CDNs. This requires the pre-signing of large amount of responses and the need to leverage expensive services that pose an evident barrier to revocation status checking.

This work provides an alternative approach that allows OCSP responders to provide only a handful of responses, thus removing the need for large CDN deployments or the need of shortening the lifetime of certificates.

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

**OCSP Request**:
          An OCSP request message, defined in [RFC6960].

**OCSP Response**:
          An OCSP Response message, defined in [RFC6960].

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

# OCSP Range Responses {#range-responses}

This document describes a new extension for the OCSP protocol that allows OCSP responders to provide responses for ranges of serial numbers that share the same status. The extension is defined as the `OCSPRange` extension and is included in the OCSP response message when the client includes the `OCSPRangeResponses` extension in the OCSP request message. In case the responder does not provide support for range queries, the responder ignores the `OCSPRangeResponses` extension and replies with a standard OCSP response that the client processes as usual.

When the responder supports range queries, instead, the responder SHALL reply with an OCSP response that carries the `OCSPRange` extension that specifies the range of certificates for which the response is valid. When range responses are used, the serial number of the CertID is set to a well-know value that the client ignores when the `OCSPRange` extension is present in the response. In that case, the client will then use the `startCertID` and `endCertID` values to check that the range set in the response covers the requested serial number.

The `startCertID` and `endCertID` values are the first and last certificate serial numbers for which the response is valid (inclusive). The `startCertID` field is required and its minimum value is zero (0). The `endCertID` is an optional field and indicates the last serial number that the response is valid for. When the value is not present, the value to use for the end of the range is `+Infinite` (meaning the largest value supported).

## The OCSP Range Queries Extension {#range-queries-extension}

When an OCSP client supports OCSP range responses, the client MUST include the `OCSPRangeResponses` extension with the value set to `NULL`. OCSP clients that do not support range queries SHALL NOT include the `OCSPRangeResponses` extension.

The extension is defined as follows:

~~~ ASN.1

id-ocsp-range-responses OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1) private(4)
    enterprise(1) OpenCA(18227) Extensions(3) id2024(2024)
    id-ocsp-range-responses(1) }

re-ocsp-range-responses EXTENSION ::= { SYNTAX NULL IDENTIFIED BY
                                        id-ocsp-range-responses }

~~~
{: #asn1-ocsp-range-response title="The OCSP Range Response Extension ASN.1 Definition"}

## The OCSPRange Extension {#ocsp-range}

When an OCSP client includes the `OCSPRangeResponses` extension in the OCSP request message, the responder MUST include the `OCSPRange` extension in the OCSP response message. The `OCSPRange` extension allows a responder to indicate the range of responses for which the response is valid. The extension is defined as follows:

~~~ ASN.1

id-ocsp-range OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1) private(4)
    enterprise(1) OpenCA(18227) Extensions(3) id2024(2024)
    id-ocsp-range(2) }

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

re-ocsp-range EXTENSION ::= { SYNTAX OCSPRange
                              IDENTIFIED BY id-ocsp-range }

~~~
{: #asn1-ocsp-range title="The OCSP Range Extension ASN.1 Definition"}

Where the `startCertID` and `endCertID` values are the first and last certificate serial numbers for which the response is valid (inclusive). If the `endCertID` is not present, the default value to use is +Infinite (meaning the largest value supported).

# Security Considerations {#sec-considerations}

The OCSP Range extension modifies the OCSP protocol by providing a mechanism to reduce the number of responses that need to be generated by the responder. The extension does not introduce new security risks, but it changes the way the responses are generated and processed. The security considerations of the OCSP protocol and CRL processing are still valid and apply to the use of the OCSP Range extension.

# IANA Considerations {#iana-considerations}

This document has no IANA actions.

--- back

# ASN.1 Module

~~~ ASN.1

<CODE STARTS>

OCSPRangeResponse-2024
    { iso(1) identified-organization(3) dod(6) internet(1)
      private(4) enterprise(1) OpenCA(18227) id-mod(2024)
      id-mod-ocsp-range-response-2024(1) }

DEFINITIONS IMPLICIT TAGS ::= BEGIN

EXPORTS ALL;

-- OCSP Range Response Extension

re-ocsp-range-responses EXTENSION ::= { SYNTAX NULL IDENTIFIED BY
                                        id-ocsp-range-responses }

-- OCSP Range Extension

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

re-ocsp-range EXTENSION ::= { SYNTAX OCSPRange
                              IDENTIFIED BY id-ocsp-range }

-- Object Identifiers

id-ocsp-range-response OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1) private(4)
    enterprise(1) OpenCA(18227) Extensions(3) id2024(2024)
    id-ocsp-range-response(1) }

id-ocsp-range OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1) private(4)
    enterprise(1) OpenCA(18227) Extensions(3) id2024(2024)
    id-ocsp-range(33) }

END

<CODE ENDS>
~~~

# OCSP Requests and Responses Processing {#back-ocsp-processing}

This section is meant to provide indications for implementers about how to properly process requests and responses that use the range queries extensions. The provisioned algorithms and examples are meant to provide guidance and are not normative.

## Processing OCSP Requests {#back-ocsp-requests-processing}

One of the advantages of using the `OCSPRange` extension is the ability to reduce the number of responses that need to be generated by the responder. For most CAs this translates in the possibility of pre-computing the responses for the ranges of certificates that share the same status (revoked or valid) and serve them directly from memory or cache.

Here's an example for how to process OCSP requests that include the `OCSPRangeResponses` extension where we use two different functions to generate the responses: `GenerateOCSPResponse` and `GenerateOCSPRangeResponse`. The first function is used to generate the standard OCSP response, while the second function is used to generate the range response.

~~~

OCSPReq <-- ReceiveOCSPRequest()

IF OCSPRangeResponse in OCSPReq.extensions THEN
    FOR idx in CachedResponses DO
        IF OCSPReq.serialNumber in CachedResponses[idx].range AND
                OCSPReq.validTo <= now THEN
            RETURN CachedResponses[idx]
        END IF
    END FOR
    OCSPResp <-- GenerateOCSPRangeResponse(OCSPReq)
    CachedResponses[OCSPReq.serialNumber] <-- OCSPResp
    RETURN OCSPResp
ELSE
    OCSPResp <-- GenerateOCSPResponse(OCSPReq)
    RETURN OCSPResp
END IF
~~~
{: #alg-ocsp-responder title="OCSP Request Processing Algorithm"}

When a responder does not support the `OCSPRangeResponses` extension, the responder SHALL ignore it and respond with a standard OCSP response that the client processes as usual.

## Processing OCSP Responses {#back-ocsp-responses-processing}

When an OCSP client receives a response from an OCSP responder, if the client supports the use of OCSPRange extensions in OCSP responses, the client processes the response according to the following algorithm:

~~~
IF OCSPRange extension is present in the response THEN

    1. Ignore the serial number used in the CertID and Use the
       startCertID and endCertID values in the OCSPRange extension
       to determine if the response is valid for the certificate
       in the request.

    2. Process the response as usual

ELSE
    1. Process the response as usual

END IF
~~~
{: #alg-ocsp-client title="OCSP Client Processing Algorithm"}

Notice that compliant clients SHALL process the OCSPRange extension even if they did not include the OCSPRangeResponses extension in the request. This is to allow the responder to provide range responses even when the client did not request them (e.g., OCSP stapling).

## Pre-Computation of OCSP Responses {#back-ocsp-precompute-responses}

To optimize the performance of the OCSP responder, the responder MAY pre-compute the responses for the ranges of active certificates population and serve them directly from memory or cache. The number of pre-computed responses includes one for each revoked certificate or range of revoked certificates plus one for each of valid certificates. An example algorithm is provided for the implementers where the responder uses the `aCRL` to lookup the list of revoked certificates (sorted) and the `Responses` array to store the pre-computed responses (sorted).

~~~ code
aStatus :== VALID;
aRangeStart :== 0;
aRangeEnd :== 0;
idx :== 0;

# Process the CRL entries
FOR EACH aEntry in aCRL.entries DO

    # Check the status of the current range
    IF aStatus == VALID THEN
        # We are in a range of valid certificates
        aRangeEnd :== aEntry.serial - 1
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

# Examples

TODO examples.

# Acknowledgments
{:numbered="false"}

TODO acknowledge.


