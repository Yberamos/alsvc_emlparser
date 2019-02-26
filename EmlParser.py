from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, constants
import email
from email.header import decode_header
import re
import sys
import quopri
import pprint
import json

sections = [
    {
        b'section_name':  b'reporter_agent',
        b'section_start': b"-----BEGIN REPORTER AGENT-----",
        b'section_end':   b"-----END REPORTER AGENT-----",
        b'fields': [
            b"Reporter agent",
            b"IP Address",
            b"Computer Name"
        ]
    },
    {
        b'section_name':  b'email_headers',
        b'section_start': b"-----BEGIN EMAIL HEADERS-----",
        b'section_end':   b"-----END EMAIL HEADERS-----"
    },
    {
        b'section_name':  b'report_count',
        b'section_start': b"-----BEGIN REPORT COUNT-----",
        b'section_end':   b"-----END REPORT COUNT-----",
        b'fields': [
            b"PhishMe emails reported",
            b"Suspicious emails reported"
        ]
    },
    {
        b'section_name':  b'urls',
        b'section_start': b"-----BEGIN URLS-----",
        b'section_end':   b"-----END URLS-----",
        b'fields': [
            b"Link text",
            b"URL",
            b"URL Domain"
        ]
    },
    {
        b'section_name':  b'attachments',
        b'section_start': b"-----BEGIN ATTACHMENTS-----",
        b'section_end':   b"-----END ATTACHMENTS-----",
        b'fields': [
            b"File Name",
            b"File Size",
            b"MD5 File Checksum",
            b"SHA1 File Checksum",
            b"SHA256 File Checksum"
        ]
    }        
]

mandatory_unique_fields = [b"Sender", b"Subject", b"Message-Id"]
unique_fields = mandatory_unique_fields + [b"On-Behalf-Of", b"Label", b"Mailbox", b"SentUtc", b"ReceivedUtc"]
recipient_fields = [b"Bcc", b"To", b"Cc", b"Recipient"]
valid_fields = unique_fields + recipient_fields

redirection_types = [b"Expanded", b"Forwarded"]
sender_fields = [b"Sender", b"On-Behalf-Of"]


class JournalRecordMessageError(Exception):
    """Base class for exceptions in the Journal Record Message module"""

class NotAJournalRecordMessageError(JournalRecordMessageError):
    """Exception raised when the message does not seem to be a Journal Record Message"""

class MalformedRecordMessageError(JournalRecordMessageError):
    """Exception raised when the Journal Record Message mail is malformed"""  

class PhishMeMailError(Exception):
    """Base class for exceptions in the PhishMe mail report module"""

class NotAPhishMeMailError(PhishMeMailError):
    """Exception raised when the message does not seem to be a PhishMe mail"""

class MalformedPhishMeMailError(PhishMeMailError):
    """Exception raised when the PhishMe mail is malformed"""



class EmlParser(ServiceBase):
    SERVICE_CATEGORY = 'Extraction'
    SERVICE_ACCEPTS = 'document/email'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_ENABLED = True
    SERVICE_STAGE = 'EXTRACT'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256
    SERVICE_DEFAULT_CONFIG = {
        'PARSE_PHISHME':False,
        'PARSE_JOURNALING':False,
    }



    def __init__(self, cfg=None):
        super(EmlParser, self).__init__(cfg)
        self.parsing_phishme=None
        self.parsing_journaling=None
    
    
    def start (self):
        self.parsing_phishme=self.cfg.get('PARSE_PHISHME', False)
        self.parsing_journaling=self.cfg.get('PARSE_JOURNALING', False)
    
    def execute(self, request):
        """Main module"""

        result = Result()
        local = request.download()
        eml_parsed=False
        found={}
        

        
        with open(local,"r") as fh:
            message = email.message_from_file(fh)

        found = self.extract_info(message)

        if self.parsing_phishme:
            try:
                found['PhishMe_Informations']=self.parse_phishme(message)
                eml_parsed=True
            except MalformedPhishMeMailError as e:
                self.log.error(e[0])
                found['PhishMe_Informations']=e[1]
                found['PhishMe_Informations']['Malformed']=True
                eml_parsed=True
            except Exception:
                pass
            
        if not eml_parsed and self.parsing_journaling:
            try:
                found['Journaling_Informations']=self.parse_journaling(message)
                eml_parsed=True
            except MalformedRecordMessageError as e:
                self.log.error(e)
            except Exception:
                pass
        
        found=self.beautify_headers(found)
        section = ResultSection(score=SCORE.NULL,title_text= "Extracted informations",body_format='JSON',body=found)
        result.add_section(section)
        request.result = result


    

    def parse_journaling(self,journal_record_message):   

        parts = journal_record_message.get_payload()



        envelope_part = parts[0]

        envelope = envelope_part.get_payload(decode=True)
        parsed_envelope = {}

        for line in envelope.split(b'\n'):
            # Skip emtpy lines
            if line.strip() == b'':
                continue

            field, value = line.split(b': ', 1)

            if field not in valid_fields:
                raise NotAJournalRecordMessageError("Probable not a Jounraling eml")
            
            if field in unique_fields:
                if field in parsed_envelope.keys():
                    raise MalformedRecordMessageError("Duplicate field: " + str(field),resut)
                else:
                    parsed_envelope[field] = value.replace('\r','')
            else:        # Field is in recipient_fields
                if b',' in value: # Recipient contains a redirection
                    forward_path, redirection = value.split(b', ', 1)
                    redirection_type, original_forward_path = redirection.split(b": ", 1)
                    if redirection_type not in redirection_types:
                        raise MalformedRecordMessageError("Unkown redirection type: " + str(redirection_type))
                else:
                    forward_path = value
                    redirection_type = None
                    original_forward_path = None

                entry = {b'forward_path': forward_path}
                if redirection_type is not None and original_forward_path is not None:
                    entry[b'redirection_type'] = redirection_type
                    entry[b'original_forward_path'] = original_forward_path

                if field in parsed_envelope.keys():
                    parsed_envelope[field].append(entry)
                else:
                    parsed_envelope[field] = [entry]
        
        for f in mandatory_unique_fields:
            if f not in parsed_envelope.keys():
                raise MalformedRecordMessageError("Missing mandatory field: " + str(f))

        return parsed_envelope

    def extract_info(self,msg):
        """Extract relevent information the the header of the eml then checks for addresses in the body in cas of a forwarded email

            Args:
            msg: an email.message.Message

            Returns:
            A dict containing all the extracted informations
        """
        info={}
        bad_chars = re.compile('[%s]' % '\t\n\r')

        for key in msg.keys():

            info[key]=bad_chars.sub('',msg.get(key))

        return info

    def parse_phishme(self,phishme_mail):
        """
        Input: a PhishMe Message in the email.message.Message format (see the email module and the email.message_from_* functions)
        Output: a dictionnary with the following keys: b'reporter_agent', b'email_headers', b'report_count', b'reported_from_folder', b'urls', b'attachments', and b'reported_message'

        * The reported_from_folder key points to a byte object with information from which folder the e-mail was reported.
            - Example data: 
                {b'Inbox'}

        * The reporter_agent key points to a dictionnary with information regarding the the reporter agent.
            - Valid keys are b'ip_address', b'reporter_agent', and b'computer_name'
            - All associated values are bytes objects.
            - Example data:
                {b'ip_address': b'127.1.2.3',
                 b'computer_name': b'COMPUTERNAME.intranet', 
                 b'reporter_agent': b'Outlook|3.0.1.0|Microsoft Windows NT 10.0.16099.0 (x64)|Outlook 16.0.0.1217'
                }

        * The email_headers key points to a is a dictionnary with the headers of the original e-mail.
            - Valid keys ate b'email_headers'
            - All associated values are bytes objects.
            - Example data:
                {b'email_headers': b'From: Sender <sender@example.com>\nTo: <receiver@example.com>\nSubject: Test\n'}
         
        * The report_count key points to a dictionnary with information regarding the reporter.
            - Valid keys are b'suspicious_emails_reported' and b'phishme_emails_reported'
            - All associated values are bytes objects.
            - Example data:
                {b'phishme_emails_reported': b'0',
                 b'suspicious_emails_reported': b'8'
                }

        * The urls key points to an array of dictionnaries about the URLs encountered in the original e-mail.
            - Valid keys are b'link_text', b'url' and b'url_domain'. Note that b'link_text' is optional.
            - All associated values are bytes objects.
            - Be aware that the URL and URL domain detection is far from perfect and sometimes reports as a domain what is in reality a part of a text sentence.
            - Example data:
            [{b'url': b'https://example[.]com/example/example.php', 
              b'link_text': b'Click here !', 
              b'url_domain': b'example[.]com'
             },
             {b'url': b'mailto:newsletter@example[.]com',
              b'url_domain': b'example[.]com'
             }
            ]
            
        * The attachments key points to an array of dictionnaries about the attachments found in the original e-mail. 
            - Valid keys are b'file_name', b'file_size', b'md5_file_checksum', b'sha1_file_checksum', and b'sha256_filechecksum'
            - All associated values are bytes objects.
            - Example data:                
            [{b'sha256_file_checksum': b'0123456789012345678901234567890123456789012345678901234567890123',                                    
              b'sha1_file_checksum': b'0123456789012345678901234567890123456789',
              b'file_size': b'1234567', 
              b'file_name': b'Title & Contents.pdf',                                 
              b'md5_file_checksum': b'01234567890123456789012345678901'
             },
             {b'sha256_file_checksum': b'7890123456789012345678901234567890123456789012345678901234567890',
              b'sha1_file_checksum': b'7890123456789012345678901234567890123456',
              b'file_size': b'8901234',
              b'file_name': b"Another file.docx",
              b'md5_file_checksum': b'78901234567890123456789012345678'
              }
            ]

        * The reported_message key points to the journaled, original, e-mail. It is an email.message.Message object.

        """
        # Skip the headers and get the contents
        parts = phishme_mail.get_payload()

        phishing_report_parts = parts[0]

        if phishing_report_parts.is_multipart():
            phishing_report_text_message = phishing_report_parts.get_payload()[0]
            phishing_report_text = phishing_report_text_message.get_payload(decode=True)
        else:
            phishing_report_text = phishing_report_parts.get_payload(decode=True)

        
        result ={
            b'reporter_agent': {},
            b'email_headers': [],
            b'report_count': {},
            b'reported_from_folder': None,
            b'urls': [],
            b'attachments': [],
            #b'reported_message': reported_message_part
        }

        lines_iterator = iter(phishing_report_text.split(b'\n'))
        for line in lines_iterator:
            line = line.strip()
            # Skip emtpy lines
            if line.strip() == b"":
                continue

            # Manage this information which is out of any other section
            if line.startswith(b"Reported from folder:"):
                result[b'reported_from_folder'] = line.split(b':', 1)[1][1:].replace('\r','')
                continue

            # The current line should be a section header. Find which one.
            section_list = (list(filter(lambda section: section[b'section_start'] == line, sections)))
            
            # There should be exactly one section matching
            if len(section_list) != 1:
                raise NotAPhishMeMailError("Section list error, probably not a PhishMe. Section list: "+str(section_list))
            section = section_list[0]

            section_name = section[b'section_name']

            if section_name == b'reporter_agent':
                for reporter_agent_line in lines_iterator:
                    reporter_agent_line = reporter_agent_line.strip()
                    if reporter_agent_line == section[b'section_end']:
                        break
                    elif reporter_agent_line == b"":
                        continue
                    else:
                        field, value = reporter_agent_line.split(b': ', 1)
                        normalized_field = field.lower().replace(b' ', b'_').replace('\r','')
                        if field not in section[b'fields']:
                            raise MalformedPhishMeMailError("In 'Reporter Agent' section, unknown field: " + str(field),result)
                        elif normalized_field in result[b'reporter_agent'].keys():
                            raise MalformedPhishMeMailError("In 'Reporter Agent' section, duplicate field: " + str(field),result)
                        else:
                            result[b'reporter_agent'][normalized_field] = value

            elif section_name == b'email_headers':
                for email_headers_line in lines_iterator:
                    email_headers_line=email_headers_line.replace('\r','')
                    if email_headers_line.strip() == section[b'section_end']:
                        break
                    else:
                        # If an header line starts with a space or tab, it is the continuation of a previous line
                        if email_headers_line.startswith(b' ') or email_headers_line.startswith(b'\t'):
                            result[b'email_headers'][-1] = result[b'email_headers'][-1] + email_headers_line
                        else:
                            result[b'email_headers'].append(email_headers_line)

            elif section_name == b'report_count':
                for report_count_line in lines_iterator:
                    report_count_line = report_count_line.strip()
                    if report_count_line == section[b'section_end']:
                        break
                    elif report_count_line == b"":
                        continue
                    else:
                        field, value = report_count_line.split(b': ', 1)
                        normalized_field = field.lower().replace(b' ', b'_')
                        if field not in section[b'fields']:
                            raise MalformedPhishMeMailError("In 'Report Count' section, unknown field: " + str(field),result)
                        elif normalized_field in result[b'report_count'].keys():
                            raise MalformedPhishMeMailError("In 'Report Count' section, duplicate field: " + str(field),result)
                        else:
                            result[b'report_count'][normalized_field] = value.replace('\r','')

            elif section_name == b'urls':
                for urls_line in lines_iterator:
                    urls_line = urls_line.strip()
                    if urls_line == section[b'section_end']:
                        break
                    elif urls_line == b"":
                        continue
                    else:
                        field, value = urls_line.split(b':', 1)
                        value = value[1:]
                        if field not in section[b'fields']:
                            raise MalformedPhishMeMailError("In 'URLS' section, unknown field: " + str(field),result)
                        else:
                            url = {}
                            if field == b"Link text":
                                url[b'link_text'] = value.replace('\r','')
                                urls_line = next(lines_iterator)
                                urls_line = urls_line.strip()

                                #skip blanks
                                while urls_line == b'':
                                    urls_line = next(lines_iterator)
                                    urls_line = urls_line.strip()

                                field, value = urls_line.split(b':', 1)
                                value = value[1:]

                            if field != b"URL":
                                raise MalformedPhishMeMailError("In 'URLS' section, expected an 'URL' field but instead got: " + str(field),result)
                            else:
                                # PhishMe URL are non-clickable because each dot is replace by [.]. Undo this 'obfuscation'
                                url[b'url'] = value.replace(b"[.]",b".").replace('\r','')
                                urls_line = next(lines_iterator)
                                urls_line = urls_line.strip()

                                #skip blanks
                                while urls_line == b'':
                                    urls_line = next(lines_iterator)
                                    urls_line = urls_line.strip()

                                field, value = urls_line.split(b':', 1)
                                value = value[1:]
                                
                            if field != b"URL Domain":
                                raise MalformedPhishMeMailError("In 'URLS' section, expected an 'URL Domain' field but instead got: " + str(field),result)
                            else:
                                # PhishMe URL are non-clickable because each dot is replace by [.]. Undo this 'obfuscation'
                                url[b'url_domain'] = value.replace(b"[.]",b".").replace('\r','')
                            result[b'urls'].append(url)
            
            elif section_name == b'attachments':
                for attachments_line in lines_iterator:
                    attachments_line = attachments_line.strip()
                    if attachments_line == section[b'section_end']:
                        break
                    elif attachments_line == b"":
                        continue
                    else:               
                        attachment = {}                 
                        for expected_field in section[b'fields']:
                            field, value = attachments_line.split(b': ', 1)
                            normalized_field = field.lower().replace(b' ', b'_')
                            if field != expected_field: 
                                raise MalformedPhishMeMailError("In 'Attachments' section, expected a '" + str(expected_field) +"' field but instead got: " + str(field),result)  
                            attachment[normalized_field] = value.replace('\r','')
                            # Is this the last field ?
                            if field != section[b'fields'][-1]:
                                attachments_line = next(lines_iterator)
                                attachments_line = attachments_line.strip()
                        result[b'attachments'].append(attachment)

        return result

    def beautify_headers(self,ugly_dict):
        beautified_headers={}
        for header in ugly_dict.keys():
            if(not header.startswith("X")):
                if header.startswith("From") or header.startswith("To") :
                    temp=decode_header(ugly_dict[header])
                    if temp[0][1] is not None:
                        decoded=temp[0][0].decode(temp[0][1],'strict')
                    else:
                        decoded=temp[0][0]
                    bad_chars = re.compile('[%s]' % '<>')
                    beautified_headers[header]=bad_chars.sub('',decoded)

                elif header.startswith("Subject") or header.startswith("Thread-Topic"):
                    temp=decode_header(ugly_dict[header])
                    if temp[0][1] is not None:
                        decoded=temp[0][0].decode(temp[0][1],'strict')
                    else:
                        decoded=temp[0][0]
                    beautified_headers[header] = decoded

                elif header.startswith("Message-ID") or\
                     header.startswith("Return-Path") or\
                     header.startswith("In-Reply-To") or\
                     header.startswith("References"):
                    bad_chars = re.compile('[%s]' % '<>')
                    beautified_headers[header]=bad_chars.sub('',ugly_dict[header])
                
                elif header.startswith("DKIM-Signature"):
                    beautified_headers[header]=self.beatify_dict(ugly_dict[header])
                
                elif header.startswith("Authentication") :
                    auth_res=ugly_dict[header].split(';')
                    for entry in auth_res:
                        if auth_res.index(entry)==0:
                            entry=entry.split(' ')
                            entry= filter(None,entry)
                            beautified_headers[header]={}
                            beautified_headers[header][header]=entry[0]
                            new_entry=entry[1].split('=')
                            beautified_headers[header][new_entry[0]]=new_entry[1]
                        elif auth_res.index(entry)%2 == 1:
                            entry=entry.replace(' ','')
                            beautified_headers[header][entry]=""
                            key=entry
                        else:
                            beautified_headers[header][key]=entry
                
                elif header.startswith("Content-Type"):
                    content=ugly_dict[header].split(';')
                    beautified_headers[header]={}
                    beautified_headers[header][header]=content[0]
                    boundary=content[1].replace(' ','')
                    beautified_headers[header]["boundary"]=boundary[9:].replace('\"','')
                
                elif header.startswith("Sender"):
                    bad_chars = re.compile('[%s]' % '<>')
                    beautified_headers[header]=bad_chars.sub('',ugly_dict[header])
                
                elif header.startswith("Journaling_Informations"):
                    beautified_headers[header]={}
                    for key in ugly_dict[header].keys():
                        if key.startswith("Message-I"):
                            bad_chars = re.compile('[%s]' % '<>')
                            beautified_headers[header][key]=bad_chars.sub('',ugly_dict[header][key])
                        elif key.startswith("Recipient"):
                            beautified_headers[header][key]={}
                            for entry in ugly_dict[header][key][0].keys():
                                beautified_headers[header][key][entry]=ugly_dict[header][key][0][entry].replace('\r','')
                        else:
                            beautified_headers[header][key]=ugly_dict[header][key]
                elif header.startswith("PhishMe_Informations"):
                    beautified_headers[header]=self.beautify_headers(ugly_dict[header])
                
                else:
                    beautified_headers[header]=ugly_dict[header]
            else:
                if header.startswith("X-YMail"):
                    bad_chars = re.compile('[%s]' % '\n\r\t ')
                    beautified_headers[header]=bad_chars.sub('',ugly_dict[header])
                elif header.startswith("X-G"):
                    if "DKIM" in header:
                        beautified_headers[header]=self.beatify_dict(ugly_dict[header])
                    else:
                        beautified_headers[header]=ugly_dict[header]
                elif header.startswith("X-Apparently-To"):
                    apparently=ugly_dict[header].split(';')
                    beautified_headers[header]=(apparently[0],apparently[1][1:])

                elif header.startswith("X-MS-Exchange-Parent-Message-Id"):
                    bad_chars = re.compile('[%s]' % '<>')
                    beautified_headers[header]=bad_chars.sub('',ugly_dict[header])
                else:
                    beautified_headers[header]=ugly_dict[header]
        return beautified_headers

    def beatify_dict(self,cat_dict):
        beautified={}
        bad_chars = re.compile('[%s]' % '\n\r\t ')
        signature=bad_chars.sub('',cat_dict)
        signature=signature.replace("=",";").split(";")
        signature= filter(None,signature)
        for entry in signature:                       
            if signature.index(entry)%2 ==0:
                beautified[entry]=""
                key=entry
            else:
                if key.startswith('b'):
                    missing_padding = len(entry) % 4
                    if missing_padding:
                        entry += b'='* (4 - missing_padding)
                beautified[key]=entry
        return beautified
                        