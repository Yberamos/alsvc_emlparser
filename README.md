# EmlParser Service

This service will parse an eml to get the relevant information.

### Execution

This service will first extract the headers from the eml, then will test if it's a specific type of eml
and extract the information for them from the body. Then it will try to beautify the data it gathered.

This service will first extract headers from a given eml using the email module, then it will attempt
to parse the file to check if it was created by one of the software selected in the options. 
To do so, the parsing method is called in a try statement with an except EXCEPTION. The try can have
4 outcomes:

* it was an eml from the software and there was no problem -> the service continue

* it was an eml from the software, but it was malformed -> log it, and store the data that were extracted

* it was not an eml from the software -> pass

* other -> pass, but log the error

This course of action was implemented to still have the service return a result even if something failed.
It will attemp to return at least the headers of the eml.


### Config (set by administrator):

PARSE_PHISHME: Activate the treatment of PhishMe eml

PARSE_JOURNALING:	Activate the treatment of Journaling eml


### Beautify:

The beautify_headers method will attemp to clean the headers extracted from the mail to remove any unwanted
characters, encode everything in utf-8 and flobally make the data more usable.
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

##### Warning:

As, at the step beautify_headers is used, all the usefull data have already been extracted, each case is encased 
in a try statement and a except EXCEPTION so as to still get a result even if the beautify for a particular headers 
fails. This means that if there's an error, that header will not be beautified but the service will still return 
the information he managed to extract at the previous step. But AssemblyLine will not show any error (the error 
message will still be in the logs).
