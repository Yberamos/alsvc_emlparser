# EmlParser Service

This service will parse an eml to get the relevant information.

## Execution

This service will first extract the headers from the eml, then will test if it's a specific type of eml
and extract the information for them from the body. Then it will try to beautify the data it gathered.

## Config (set by administrator):

PARSE_PHISHME: Activate the treatment of PhishMe eml

PARSE_JOURNALING:	Activate the treatment of Journaling eml


## Warning:

### Exception:
To still get a result if the beautify fails, each case in it is encased in a try statement with an 
except EXCEPTION. This means that if there's an error, that header will not be beautified but
the service will still return the information he managed to extract at the previous step. But 
AssemblyLine will not show any error (the error message will still be in the logs).

An except EXCEPTION is also used while testing if an eml is of the specific types ask. It's used there as
the parsing method for those types is used and it will raise an exception if it's not.

### Beautify:
A beautifu method is included in the service but as every pice of software and every mail box will
add different headers, the method might not beautify every header in the eml.
