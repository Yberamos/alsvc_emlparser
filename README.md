# EmlParser Service

This service will parse a eml to get the relevent information.

## Execution

This service will first extract the headers from the eml, then will test if it's a specific type of eml
and extract the information for them from the body. Then it will try to beautify the data it gathered.
The service uses the 7zip library to extract files out of containers then resubmits them for analysis.


## Config (set by administrator):

PARSE_PHISHME: Activate the treatment of PhishMe eml

PARSE_JOURNALING:	Activate the treatment of Journaling eml

## Warning:

To still get a result if the beautify fails, each case in it is incased in a try statement with an 
except EXCEPTION. This mean,s that if there's an error, that header will not be beautyfied but
the service will still return the information he managed to extract a the previous step. But 
AssemblyLine will not show any error (the error message will still be in the logs).

An except ECEPTION is also used while testing if an eml is of the specific types ask. It's used there as
the parsing method for those types is used and it will raised an exception if it's not.







