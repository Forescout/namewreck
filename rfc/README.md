# Common implementation anti-patterns related to DNS resource record processing (Internet-Draft)

This folder contains an Informational Internet-Draft document
(`draft-dashevskyi-dnsrr-antipatterns-00.txt`) that we submitted on March 23,
2021. 

The document describes common vulnerabilities related to DNS response record
processing as seen in several DNS client implementations (part of the NAME:WRECK
research that belongs to the [Project
Memoria](https://www.forescout.com/research-labs/) initiative). These
vulnerabilities may lead to successful Denial-of-Service and Remote Code
Execution attacks against the affected software. Where applicable, violations of
RFC 1035 are mentioned. 

The main purpose of the document is to provide technical details behind these
anti-patterns, so that the common mistakes can be eradicated.
