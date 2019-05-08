# EmlParser Service

This service will parse an eml to get the relevant information.

### Execution

This service will first extract the headers from the eml, then will test if it's a specific type of eml
and extract the information for them from the body. Finally it will try to beautify the data it gathered.

This service will first extract headers from a given eml using the python email module, then it will attempt
to parse the body to check if this body matches one of the format/template selected in the options. 
To do so, the parsing method is called in a try statement. The try can have 4 outcomes:

* this template has matched the body  and there was no problem -> the service continue

* there was a match with a template, but it was malformed -> log it, and store the data that were extracted

* no template has matched -> pass

This course of action was implemented to still have the service return a result even if something failed.
It will attempt to return at least the headers of the eml.


### Config (set by administrator):

PARSE_PHISHME: Activate the processing of PhishMe eml

PARSE_JOURNALING: Activate the processing of Exchange journaling eml


### Beautify:

The beautify_headers method will attempt to clean the headers extracted from the mail to remove any unwanted
characters, encode everything in utf-8 and globally make the data more usable.
It can clean:

* To

* From 

* Subject

* Thread-Topic

* Message-ID

* Return-Path

* In-Reply-To

* References

* DKIM-Signature

* Authentication

* Content-Type

* Sender

* ARC-Message-Signature

* ARC-Authentication-Results

* X-YMail

* X-Google-DKIM-Signature

* X-Apparently-To

* X-MS-Exchange-Parent-Message-Id

* X-MS-Exchange-Forest-IndexAgent

Every beautify is encased in a try statement to still return the result (not beautified) even if it's not in the expected format.
