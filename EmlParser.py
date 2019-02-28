from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE
import email
from email.header import decode_header
import re
import traceback

sections = [
    {
        'section_name':  'reporter_agent',
        'section_start': "-----BEGIN REPORTER AGENT-----",
        'section_end':   "-----END REPORTER AGENT-----",
        'fields': [
            "Reporter agent",
            "IP Address",
            "Computer Name"
        ]
    },
    {
        'section_name':  'email_headers',
        'section_start': "-----BEGIN EMAIL HEADERS-----",
        'section_end':   "-----END EMAIL HEADERS-----"
    },
    {
        'section_name':  'report_count',
        'section_start': "-----BEGIN REPORT COUNT-----",
        'section_end':   "-----END REPORT COUNT-----",
        'fields': [
            "PhishMe emails reported",
            "Suspicious emails reported"
        ]
    },
    {
        'section_name':  'urls',
        'section_start': "-----BEGIN URLS-----",
        'section_end':   "-----END URLS-----",
        'fields': [
            "Link text",
            "URL",
            "URL Domain"
        ]
    },
    {
        'section_name':  'attachments',
        'section_start': "-----BEGIN ATTACHMENTS-----",
        'section_end':   "-----END ATTACHMENTS-----",
        'fields': [
            "File Name",
            "File Size",
            "MD5 File Checksum",
            "SHA1 File Checksum",
            "SHA256 File Checksum"
        ]
    }        
]

mandatory_unique_fields = ["Sender", "Subject", "Message-Id"]
unique_fields = mandatory_unique_fields + ["On-Behalf-Of", "Label", "Mailbox", "SentUtc", "ReceivedUtc"]
recipient_fields = ["Bcc", "To", "Cc", "Recipient"]
valid_fields = unique_fields + recipient_fields

redirection_types = ["Expanded", "Forwarded"]
sender_fields = ["Sender", "On-Behalf-Of"]


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
    SERVICE_CATEGORY = 'Metadata'
    SERVICE_ACCEPTS = 'document/email'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_ENABLED = True
    SERVICE_STAGE = 'CORE'
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
        found['Eml_type']="Default"

        if self.parsing_phishme:
            try:
                found['PhishMe_Informations']=self.parse_phishme(message)
                eml_parsed=True
                found['Eml_type']="PhishMe"
            except MalformedPhishMeMailError as e:
                self.log.error(e.args[0])
                found['PhishMe_Informations']=e[1]
                found['PhishMe_Informations']['Malformed']=True
                found['Eml_type']="PhishMe"
                eml_parsed=True
            except Exception:
                pass
            
        if not eml_parsed and self.parsing_journaling:
            try:
                found['Journaling_Informations']=self.parse_journaling(message)
                eml_parsed=True
                found['Eml_type']="Journaling"
            except MalformedRecordMessageError as e:
                self.log.exception(e)
            except Exception:
                pass
        
        try:
            found=self.beautify_headers(found)
        except Exception as e:
            self.log.exception(e)
        section = ResultSection(score=SCORE.NULL,title_text= "Extracted informations",body_format='JSON',body=found)
        result.add_section(section)
        request.result = result


    

    def parse_journaling(self,journal_record_message):   
        """
        Input: a Journal Record Message in the email.message.Message format (see the email module and the email.message_from_* functions)
        Output: a tuple of (journal_record_message_headers, parsed_envelope, original_message_part)
            * journal_record_message_headers are the headers of the Journal Record Message (i.e. the enclosing message). It is a list of 2-uples and it provided by the email module.
                - The first element of the tuple is the name of the header (e.g. From, To, Subject, Date, ...), the second is the value of the headers. 
                - It is a list of tuples and not a dictionnary because there is no warranty that a header will appear only once in an e-mail headers.
                - Example data:
                    [('Subject', 'Test'), ('To', '"Test" <test@example.com>'), ('From', 'sender@example.com')]
        #TODO: is it useful
            * parsed_envelope are the journaling meta-data. It is a dict. 
                - The key is the name of the field name, and the value is its value. See the Journal Record Message File Format specification.
                - All associated values are bytes objects.
                - Note that the value associated with recipients fields (e.g. to, cc, ...) is an array of dict. 
                    It is an array because the journaling data may contain multiple occurence of the same recipient field (e.g. multiple to: lines).
                    It is an array of dict because each recipient may contain not only the recipient adress but also a redirection type and a redirection adress.
                - Valid keys for the journaling data dict are: "sender", "subject", "message-id", "on-behalf-of", "label", "mailbox", "sentutc", "receivedutc", 
                  "bcc", "to", "cc", and "recipient"
                - If the entry is keyed by "to", "cc", "bcc", or "recipient", the valid keys for the returned dict are "forward_path", "redirection_type", 
                  and "original_forward_path"
                - "forward_path" and "original_forward_path" entries are e-mail adresses encoded as string.
                - "redirection_type" entries are string with a value of either "Expanded" or "Forwarded"
                - Example data: 
                    {'recipient': [{'original_forward_path': 'test@example.com', 'redirection_type': 'Expanded', 'forward_path': 'mailing-list@example.com'}], 
                     'message-id': '<ABCDEF0123456ABCDEF0123456789ABCDEF012@ABCDEF0123456.example.com>',
                     'subject': 'Test test test',
                     'sender': 'sender@example.com'}


            * original_message_part is the journaled, original, e-mail. It is an email.message.Message object.
        """
        parts = journal_record_message.get_payload()



        envelope_part = parts[0]

        envelope = envelope_part.get_payload(decode=True)
        parsed_envelope = {}

        for line in envelope.split('\n'):
            # Skip emtpy lines
            if line.strip() == '':
                continue

            field, value = line.split(': ', 1)

            if field not in valid_fields:
                raise NotAJournalRecordMessageError("Probable not a Jounraling eml")
            
            if field in unique_fields:
                if field in parsed_envelope.keys():
                    raise MalformedRecordMessageError("Duplicate field: " + str(field),parsed_envelope)
                else:
                    parsed_envelope[field] = value.replace('\r','')
            else:        # Field is in recipient_fields
                if ',' in value: # Recipient contains a redirection
                    forward_path, redirection = value.split(', ', 1)
                    redirection_type, original_forward_path = redirection.split(": ", 1)
                    if redirection_type not in redirection_types:
                        raise MalformedRecordMessageError("Unkown redirection type: " + str(redirection_type))
                else:
                    forward_path = value
                    redirection_type = None
                    original_forward_path = None

                entry = {'forward_path': forward_path}
                if redirection_type is not None and original_forward_path is not None:
                    entry['redirection_type'] = redirection_type
                    entry['original_forward_path'] = original_forward_path

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
        Output: a dictionnary with the following keys: 'reporter_agent', 'email_headers', 'report_count', 'reported_from_folder', 'urls', 'attachments', and 'reported_message'

        * The reported_from_folder key points to a byte object with information from which folder the e-mail was reported.
            - Example data: 
                {'Inbox'}

        * The reporter_agent key points to a dictionnary with information regarding the the reporter agent.
            - Valid keys are 'ip_address', 'reporter_agent', and 'computer_name'
            - All associated values are bytes objects.
            - Example data:
                {'ip_address': '127.1.2.3',
                 'computer_name': 'COMPUTERNAME.intranet', 
                 'reporter_agent': 'Outlook|3.0.1.0|Microsoft Windows NT 10.0.16099.0 (x64)|Outlook 16.0.0.1217'
                }

        * The email_headers key points to a is a dictionnary with the headers of the original e-mail.
            - Valid keys ate 'email_headers'
            - All associated values are bytes objects.
            - Example data:
                {'email_headers': 'From: Sender <sender@example.com>\nTo: <receiver@example.com>\nSubject: Test\n'}
         
        * The report_count key points to a dictionnary with information regarding the reporter.
            - Valid keys are 'suspicious_emails_reported' and 'phishme_emails_reported'
            - All associated values are bytes objects.
            - Example data:
                {'phishme_emails_reported': '0',
                 'suspicious_emails_reported': '8'
                }

        * The urls key points to an array of dictionnaries about the URLs encountered in the original e-mail.
            - Valid keys are 'link_text', 'url' and 'url_domain'. Note that 'link_text' is optional.
            - All associated values are bytes objects.
            - Be aware that the URL and URL domain detection is far from perfect and sometimes reports as a domain what is in reality a part of a text sentence.
            - Example data:
            [{'url': 'https://example[.]com/example/example.php', 
              'link_text': 'Click here !', 
              'url_domain': 'example[.]com'
             },
             {'url': 'mailto:newsletter@example[.]com',
              'url_domain': 'example[.]com'
             }
            ]
            
        * The attachments key points to an array of dictionnaries about the attachments found in the original e-mail. 
            - Valid keys are 'file_name', 'file_size', 'md5_file_checksum', 'sha1_file_checksum', and 'sha256_filechecksum'
            - All associated values are bytes objects.
            - Example data:                
            [{'sha256_file_checksum': '0123456789012345678901234567890123456789012345678901234567890123',                                    
              'sha1_file_checksum': '0123456789012345678901234567890123456789',
              'file_size': '1234567', 
              'file_name': 'Title & Contents.pdf',                                 
              'md5_file_checksum': '01234567890123456789012345678901'
             },
             {'sha256_file_checksum': '7890123456789012345678901234567890123456789012345678901234567890',
              'sha1_file_checksum': '7890123456789012345678901234567890123456',
              'file_size': '8901234',
              'file_name': "Another file.docx",
              'md5_file_checksum': '78901234567890123456789012345678'
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
            'reporter_agent': {},
            'email_headers': [],
            'report_count': {},
            'reported_from_folder': None,
            'urls': [],
            'attachments': [],
            #'reported_message': reported_message_part
        }

        lines_iterator = iter(phishing_report_text.split('\n'))
        for line in lines_iterator:
            line = line.strip()
            # Skip emtpy lines
            if line.strip() == "":
                continue

            # Manage this information which is out of any other section
            if line.startswith("Reported from folder:"):
                result['reported_from_folder'] = line.split(':', 1)[1][1:].replace('\r','')
                continue

            # The current line should be a section header. Find which one.
            section_list = (list(filter(lambda section: section['section_start'] == line, sections)))
            
            # There should be exactly one section matching
            if len(section_list) != 1:
                raise NotAPhishMeMailError("Section list error, probably not a PhishMe. Section list: "+str(section_list))
            section = section_list[0]

            section_name = section['section_name']

            if section_name == 'reporter_agent':
                for reporter_agent_line in lines_iterator:
                    reporter_agent_line = reporter_agent_line.strip()
                    if reporter_agent_line == section['section_end']:
                        break
                    elif reporter_agent_line == "":
                        continue
                    else:
                        field, value = reporter_agent_line.split(': ', 1)
                        normalized_field = field.lower().replace(' ', '_').replace('\r','')
                        if field not in section['fields']:
                            raise MalformedPhishMeMailError("In 'Reporter Agent' section, unknown field: " + str(field),result)
                        elif normalized_field in result['reporter_agent'].keys():
                            raise MalformedPhishMeMailError("In 'Reporter Agent' section, duplicate field: " + str(field),result)
                        else:
                            result['reporter_agent'][normalized_field] = value

            elif section_name == 'email_headers':
                for email_headers_line in lines_iterator:
                    email_headers_line=email_headers_line.replace('\r','')
                    if email_headers_line.strip() == section['section_end']:
                        break
                    else:
                        # If an header line starts with a space or tab, it is the continuation of a previous line
                        if email_headers_line.startswith(' ') or email_headers_line.startswith('\t'):
                            result['email_headers'][-1] = result['email_headers'][-1] + email_headers_line
                        else:
                            result['email_headers'].append(email_headers_line)

            elif section_name == 'report_count':
                for report_count_line in lines_iterator:
                    report_count_line = report_count_line.strip()
                    if report_count_line == section['section_end']:
                        break
                    elif report_count_line == "":
                        continue
                    else:
                        field, value = report_count_line.split(': ', 1)
                        normalized_field = field.lower().replace(' ', '_')
                        if field not in section['fields']:
                            raise MalformedPhishMeMailError("In 'Report Count' section, unknown field: " + str(field),result)
                        elif normalized_field in result['report_count'].keys():
                            raise MalformedPhishMeMailError("In 'Report Count' section, duplicate field: " + str(field),result)
                        else:
                            result['report_count'][normalized_field] = value.replace('\r','')

            elif section_name == 'urls':
                for urls_line in lines_iterator:
                    urls_line = urls_line.strip()
                    if urls_line == section['section_end']:
                        break
                    elif urls_line == "":
                        continue
                    else:
                        field, value = urls_line.split(':', 1)
                        value = value[1:]
                        if field not in section['fields']:
                            raise MalformedPhishMeMailError("In 'URLS' section, unknown field: " + str(field),result)
                        else:
                            url = {}
                            if field == "Link text":
                                url['link_text'] = value.replace('\r','')
                                urls_line = next(lines_iterator)
                                urls_line = urls_line.strip()

                                #skip blanks
                                while urls_line == '':
                                    urls_line = next(lines_iterator)
                                    urls_line = urls_line.strip()

                                field, value = urls_line.split(':', 1)
                                value = value[1:]

                            if field != "URL":
                                raise MalformedPhishMeMailError("In 'URLS' section, expected an 'URL' field but instead got: " + str(field),result)
                            else:
                                # PhishMe URL are non-clickable because each dot is replace by [.]. Undo this 'obfuscation'
                                url['url'] = value.replace("[.]",".").replace('\r','')
                                urls_line = next(lines_iterator)
                                urls_line = urls_line.strip()

                                #skip blanks
                                while urls_line == '':
                                    urls_line = next(lines_iterator)
                                    urls_line = urls_line.strip()

                                field, value = urls_line.split(':', 1)
                                value = value[1:]
                                
                            if field != "URL Domain":
                                raise MalformedPhishMeMailError("In 'URLS' section, expected an 'URL Domain' field but instead got: " + str(field),result)
                            else:
                                # PhishMe URL are non-clickable because each dot is replace by [.]. Undo this 'obfuscation'
                                url['url_domain'] = value.replace("[.]",".").replace('\r','')
                            result['urls'].append(url)
            
            elif section_name == 'attachments':
                for attachments_line in lines_iterator:
                    attachments_line = attachments_line.strip()
                    if attachments_line == section['section_end']:
                        break
                    elif attachments_line == "":
                        continue
                    else:               
                        attachment = {}                 
                        for expected_field in section['fields']:
                            field, value = attachments_line.split(': ', 1)
                            normalized_field = field.lower().replace(' ', '_')
                            if field != expected_field: 
                                raise MalformedPhishMeMailError("In 'Attachments' section, expected a '" + str(expected_field) +"' field but instead got: " + str(field),result)  
                            attachment[normalized_field] = value.replace('\r','')
                            # Is this the last field ?
                            if field != section['fields'][-1]:
                                attachments_line = next(lines_iterator)
                                attachments_line = attachments_line.strip()
                        result['attachments'].append(attachment)

        return result

    def beautify_headers(self,ugly_dict):
        """Clean known headers if found in the dict

            Args:
            ugly_dict: a dict that contains eml headers and their values

            Returns:
            A nice and clean dict
        """
        beautified_headers={}
        for header in ugly_dict.keys():
            if(not header.startswith("X")):
                #RFC822 headers or personalised entry in the dict
                if header.startswith("From") or header.startswith("To") :
                    try:
                        temp=decode_header(ugly_dict[header]) 
                        if temp[0][1] is not None: #check if it's encoded
                            decoded=temp[0][0].decode(temp[0][1],'strict')
                        else:
                            decoded=temp[0][0]
                        bad_chars = re.compile('[%s]' % '<>')
                        beautified_headers[header]=bad_chars.sub('',decoded)
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]


                elif header.startswith("Subject") or header.startswith("Thread-Topic"):
                    
                    try:
                        temp=decode_header(ugly_dict[header])
                        if temp[0][1] is not None: #check if it's encoded
                            decoded=temp[0][0].decode(temp[0][1],'strict')
                        else:
                            decoded=temp[0][0]
                        beautified_headers[header] = decoded
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]

                elif header.startswith("Message-ID") or\
                     header.startswith("Return-Path") or\
                     header.startswith("In-Reply-To") or\
                     header.startswith("References"):
                    try:
                        bad_chars = re.compile('[%s]' % '<>')
                        beautified_headers[header]=bad_chars.sub('',ugly_dict[header])
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]
                
                elif header.startswith("DKIM-Signature"): #the DKIM-signature is a dict concatenate as a string
                    try:
                        beautified_headers[header]=self.beatify_dict(ugly_dict[header])
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]
                
                elif header.startswith("Authentication") : #same as DKIM-signature but much simpler
                    try:
                        auth_res=ugly_dict[header].split(';') 
                        beautified_headers[header]=[] 
                        for entry in auth_res:
                            start=re.search(r'[a-z]',entry).start()
                            beautified_headers[header].append(entry[start:])
                            
                    except Exception as e:
                        self.log.exception(e)
                        print request.path
                        beautified_headers[header]=ugly_dict[header]
                
                elif header.startswith("Content-Type"):
                    try:
                        content=ugly_dict[header].split(';')
                        beautified_headers[header]={}
                        beautified_headers[header][header]=content[0]
                        if len(content)>1:
                            boundary=content[1].replace(' ','')
                            beautified_headers[header]["boundary"]=boundary[9:].replace('\"','') #the baundary fieled can sometimes be boundary="----=_Part_35139" the 2nd '=' being part of the boundary
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]

                elif header.startswith("Sender"):
                    try:
                        bad_chars = re.compile('[%s]' % '<>')
                        beautified_headers[header]=bad_chars.sub('',ugly_dict[header])
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]

                elif header.startswith("Journaling_Informations"): 
                    try:
                        beautified_headers[header]={}
                        for key in ugly_dict[header].keys():
                            if key.startswith("Message-I"):
                                bad_chars = re.compile('[%s]' % '<>')
                                beautified_headers[header][key]=bad_chars.sub('',ugly_dict[header][key])
                            elif key.startswith("Recipient"): 
                                beautified_headers[header][key]={}
                                for entry in ugly_dict[header][key][0].keys():
                                    beautified_headers[header][key][entry]=ugly_dict[header][key][0][entry].replace('\r','') #instead of having a list  with all the adresses in a dictionary with only one entry, move everything up into the dictionary
                            else:
                                beautified_headers[header][key]=ugly_dict[header][key]
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]

                elif header.startswith("PhishMe_Informations"):
                    try:
                        beautified_headers[header]=self.beautify_headers(ugly_dict[header])
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]
                
                elif header.startswith("ARC"):
                    if header.startswith("ARC-Message-Signature")\
                    or header.startswith("ARC-Seal"):
                        try:
                            beautified_headers[header]=self.beatify_dict(ugly_dict[header])
                        except Exception as e:
                            self.log.exception(e)
                            beautified_headers[header]=ugly_dict[header]

                    elif header.startswith("ARC-Authentication-Results"):
                        
                        try:
                            auth_res=ugly_dict[header].split(';') 
                            beautified_headers[header]=[] 
                            for entry in auth_res:
                                start=re.search(r'[a-z]',entry).start()
                                beautified_headers[header].append(entry[start:])
                                
                        except Exception as e:
                            self.log.exception(e)
                            print request.path
                            beautified_headers[header]=ugly_dict[header]
                    else:
                        beautified_headers[header]=ugly_dict[header]
                
                elif header.startswith("email_headers"):
                    try:
                        beautified_headers[header]={}
                        for s in ugly_dict[header]:
                            index = s.index(":")
                            key = s[:index]
                            value = s[index+2:]
                            if key in beautified_headers[header].keys():  
                                if not isinstance(beautified_headers[header][key],list):
                                    temp=beautified_headers[header][key]
                                    beautified_headers[header][key]=[]
                                    beautified_headers[header][key].append(temp)
                                beautified_headers[header][key].append(value)
                                continue
                            beautified_headers[header][key]=value
                        beautified_headers[header]=self.beautify_headers(beautified_headers[header])
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]
                elif header.startswith("received") or header.startswith("Received") :
                    try:
                        if isinstance(ugly_dict[header],list):
                            beautified_headers[header]=[]
                            for s in ugly_dict[header]:
                                beautified_headers[header].append(s)
                        else:
                            beautified_headers[header]=ugly_dict[header]
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]

                    beautified_headers[header]=ugly_dict[header]
            else: #all the non-rfc822 headers (client dependant)
                if header.startswith("X-YMail"): #Yahoo mail headers
                    try:
                        bad_chars = re.compile('[%s]' % '\n\r\t ')
                        beautified_headers[header]=bad_chars.sub('',ugly_dict[header])
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]

                elif header.startswith("X-G"): #GMail headers
                    try:
                        if "DKIM" in header:
                            beautified_headers[header]=self.beatify_dict(ugly_dict[header])
                        else:
                            beautified_headers[header]=ugly_dict[header]
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]

                elif header.startswith("X-Apparently-To"):
                    try:
                        apparently=ugly_dict[header].split(';')
                        beautified_headers[header]=(apparently[0],apparently[1][1:])
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]

                elif header.startswith("X-MS-Exchange-Parent-Message-Id"):#Miscrosft Exchange headers
                    try:
                        bad_chars = re.compile('[%s]' % '<>')
                        beautified_headers[header]=bad_chars.sub('',ugly_dict[header])
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header]=ugly_dict[header]
                else:
                    beautified_headers[header]=ugly_dict[header]
        return beautified_headers

    def beatify_dict(self,cat_dict):
        """Split a string into a dictionary

            Args:
            cat_dict: a dictionary that is in a string format

            Returns:
            the dictionary generated from the string
        """
        beautified={}
        bad_chars = re.compile('[%s]' % '\n\r\t ')
        signature=bad_chars.sub('',cat_dict) #remove all the control char while it's still a string
        signature=signature.replace("=",";").split(";")
        signature= filter(None,signature)
        for entry in signature:                       
            if signature.index(entry)%2 ==0: #the elements in the list will have the order= key value key value key value
                beautified[entry]=""
                key=entry
            else:
                if key.startswith('b'): #those entry are suposed to be in b64 but all the '=' were remover to split the keys and values (therefore, the padding is gone)
                    missing_padding = len(entry) % 4
                    if missing_padding:
                        entry += '='* (4 - missing_padding)
                beautified[key]=entry
        return beautified
                        