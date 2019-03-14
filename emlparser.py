"""
- Note that the value associated with recipients fields (e.g. to, cc, ...) is an array of dict.
It is an array because the journaling data may contain multiple occurrence of the same recipient field (e.g. multiple to: lines).
It is an array of dict because each recipient may contain not only the recipient address but also a redirection type and a redirection address.
"""

import email
import re
from email.header import decode_header
import pprint
import quopri
import chardet

from assemblyline.al.common.result import Result, ResultSection, SCORE
from assemblyline.al.service.base import ServiceBase

sections = [
    {
        'section_name': 'reporter_agent',
        'section_start': "-----BEGIN REPORTER AGENT-----",
        'section_end': "-----END REPORTER AGENT-----",
        'fields': [
            "Reporter agent",
            "IP Address",
            "Computer Name"
        ]
    },
    {
        'section_name': 'email_headers',
        'section_start': "-----BEGIN EMAIL HEADERS-----",
        'section_end': "-----END EMAIL HEADERS-----"
    },
    {
        'section_name': 'report_count',
        'section_start': "-----BEGIN REPORT COUNT-----",
        'section_end': "-----END REPORT COUNT-----",
        'fields': [
            "PhishMe emails reported",
            "Suspicious emails reported"
        ]
    },
    {
        'section_name': 'urls',
        'section_start': "-----BEGIN URLS-----",
        'section_end': "-----END URLS-----",
        'fields': [
            "Link text",
            "URL",
            "URL Domain"
        ]
    },
    {
        'section_name': 'attachments',
        'section_start': "-----BEGIN ATTACHMENTS-----",
        'section_end': "-----END ATTACHMENTS-----",
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
    SERVICE_STAGE = 'EXTRACT'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256
    SERVICE_DEFAULT_CONFIG = {
        'PARSE_PHISHME': False,
        'PARSE_JOURNALING': False,
    }

    def __init__(self, cfg=None):
        super(EmlParser, self).__init__(cfg)
        self.parsing_phishme = None
        self.parsing_journaling = None


    def start(self):
        self.parsing_phishme = self.cfg.get('PARSE_PHISHME', False)
        self.parsing_journaling = self.cfg.get('PARSE_JOURNALING', False)

    def execute(self, request):
        """Main module"""

        result = Result()
        local = request.download()
        eml_parsed = False
        found = {}
        with open(local, "r") as fh:
            message = email.message_from_file(fh)

        found = self.extract_info(message)

        found['Eml_type'] = "Default"
        if self.parsing_phishme:
            try:
                found['PhishMe_Information'] = self.parse_phishme(message)
                eml_parsed = True
                found['Eml_type'] = "PhishMe"
            except MalformedPhishMeMailError as e:
                self.log.error(e.args[0])
                found['PhishMe_Information'] = e[1]
                found['PhishMe_Information']['Malformed'] = True
                found['Eml_type'] = "PhishMe"
                eml_parsed = True
            except Exception:
                pass

        if not eml_parsed and self.parsing_journaling:
            try:
                found['Journaling_Information'] = self.parse_journaling(message)
                eml_parsed = True
                found['Eml_type'] = "Journaling"
            except MalformedRecordMessageError as e:
                self.log.error(e)
            except Exception as e:
                self.log.error(e)
                pass

        try:
            found = self.beautify_headers(found)
        except Exception as e:
            self.log.error(e)
        section = ResultSection(score=SCORE.NULL, title_text="Extracted information", body_format='JSON', body=found)
        result.add_section(section)
        request.result = result

    @staticmethod
    def parse_journaling(journal_record_message):
        """
            Input: a Journal Record Message in the email.message.Message format
            Output: a dict with the relevant information extracted from the mail
        """
        parts = journal_record_message.get_payload()

        envelope_part = parts[0]

        envelope = envelope_part.get_payload(decode=True)
        parsed_envelope = {}

        for line in envelope.split('\n'):
            # Skip empty lines
            if line.strip() == '':
                continue

            field, value = line.split(': ', 1)

            if field not in valid_fields:
                raise NotAJournalRecordMessageError("Probable not a Journaling eml")

            if field in unique_fields:
                if field in parsed_envelope.keys():
                    raise MalformedRecordMessageError("Duplicate field: " + str(field), parsed_envelope)
                else:
                    parsed_envelope[field] = value.replace('\r', '')
            else:  # Field is in recipient_fields
                if ',' in value:  # Recipient contains a redirection
                    forward_path, redirection = value.split(', ', 1)
                    redirection_type, original_forward_path = redirection.split(": ", 1)
                    if redirection_type not in redirection_types:
                        raise MalformedRecordMessageError("Unknown redirection type: " + str(redirection_type))
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

    @staticmethod
    def extract_info(msg):
        """
            Process:
                Extract relevant information the the header of the eml then checks for addresses in
                the body in case of a forwarded email

            Input:
                msg: an email.message.Message

            Output:
                A dict containing all the extracted informations
        """
        info = {}
        bad_chars = re.compile('[%s]' % '\t\n\r')

        for key in msg.keys():
            info[key] = bad_chars.sub('', msg.get(key))

        return info

    @staticmethod
    def parse_phishme(phishme_mail):
        """
        Input: a  Message
        Output: a dictionary with the following keys: 'reporter_agent', 'email_headers', 'report_count',
            'reported_from_folder', 'urls', 'attachments', and 'reported_message'
        """
        # Skip the headers and get the contents
        parts = phishme_mail.get_payload()

        phishing_report_parts = parts[0]

        if phishing_report_parts.is_multipart():
            phishing_report_text_message = phishing_report_parts.get_payload()[0]
            phishing_report_text = phishing_report_text_message.get_payload(decode=True)
        else:
            phishing_report_text = phishing_report_parts.get_payload(decode=True)

        result = {
            'reporter_agent': {},
            'email_headers': [],
            'report_count': {},
            'reported_from_folder': None,
            'urls': [],
            'attachments': [],
        }

        lines_iterator = iter(phishing_report_text.split('\n'))
        for line in lines_iterator:
            line = line.strip()
            # Skip empty lines
            if line.strip() == "":
                continue

            # Manage this information which is out of any other section
            if line.startswith("Reported from folder:"):
                result['reported_from_folder'] = line.split(':', 1)[1][1:].replace('\r', '')
                continue

            # The current line should be a section header. Find which one.
            section_list = (list(filter(lambda section: section['section_start'] == line, sections)))

            # There should be exactly one section matching
            if len(section_list) != 1:
                raise NotAPhishMeMailError(
                    "Section list error, probably not a PhishMe. Section list: " + str(section_list))
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
                        normalized_field = field.lower().replace(' ', '_').replace('\r', '')
                        if field not in section['fields']:
                            raise MalformedPhishMeMailError("In 'Reporter Agent' section, unknown field: " + str(field),
                                                            result)
                        elif normalized_field in result['reporter_agent'].keys():
                            raise MalformedPhishMeMailError(
                                "In 'Reporter Agent' section, duplicate field: " + str(field), result)
                        else:
                            result['reporter_agent'][normalized_field] = value

            elif section_name == 'email_headers':
                for email_headers_line in lines_iterator:
                    email_headers_line = email_headers_line.replace('\r', '')
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
                            raise MalformedPhishMeMailError("In 'Report Count' section, unknown field: " + str(field),
                                                            result)
                        elif normalized_field in result['report_count'].keys():
                            raise MalformedPhishMeMailError("In 'Report Count' section, duplicate field: " + str(field),
                                                            result)
                        else:
                            result['report_count'][normalized_field] = value.replace('\r', '')

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
                            raise MalformedPhishMeMailError("In 'URLS' section, unknown field: " + str(field), result)
                        else:
                            url = {}
                            if field == "Link text":
                                url['link_text'] = value.replace('\r', '')
                                urls_line = next(lines_iterator)
                                urls_line = urls_line.strip()

                                # skip blanks
                                while urls_line == '':
                                    urls_line = next(lines_iterator)
                                    urls_line = urls_line.strip()

                                field, value = urls_line.split(':', 1)
                                value = value[1:]

                            if field != "URL":
                                raise MalformedPhishMeMailError(
                                    "In 'URLS' section, expected an 'URL' field but instead got: " + str(field), result)
                            else:
                                # PhishMe URL are non-clickable because each dot is replace by [.]
                                url['url'] = value.replace("[.]", ".").replace('\r', '')
                                urls_line = next(lines_iterator)
                                urls_line = urls_line.strip()

                                # skip blanks
                                while urls_line == '':
                                    urls_line = next(lines_iterator)
                                    urls_line = urls_line.strip()

                                field, value = urls_line.split(':', 1)
                                value = value[1:]

                            if field != "URL Domain":
                                raise MalformedPhishMeMailError(
                                    "In 'URLS' section, expected an 'URL Domain' field but instead got: " + str(field),
                                    result)
                            else:
                                # PhishMe URL are non-clickable because each dot is replace by [.]
                                url['url_domain'] = value.replace("[.]", ".").replace('\r', '')
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
                                raise MalformedPhishMeMailError("In 'Attachments' section, expected a '" + str(
                                    expected_field) + "' field but instead got: " + str(field), result)
                            attachment[normalized_field] = value.replace('\r', '')
                            # Is this the last field ?
                            if field != section['fields'][-1]:
                                attachments_line = next(lines_iterator)
                                attachments_line = attachments_line.strip()
                        result['attachments'].append(attachment)

        return result

    @staticmethod
    def beatify_dict(cat_dict):
        """
            Process:
                Split a string into a dictionary

            Input:
                cat_dict: a dictionary that is in a string format

            Output:
                the dictionary generated from the string
        """
        beautified = {}
        print
        print
        print
        print
        pprint.pprint(cat_dict)
        print
        print
        print
        print
        bad_chars = re.compile('[%s]' % '\n\r\t ')
        signature = bad_chars.sub('', cat_dict)  # remove all the control char while it's still a string
        signature = signature.replace("=", ";").split(";")
        signature = filter(None, signature)
        for entry in signature:
            # the elements in the list will have the order= key value key value key value
            if signature.index(entry) % 2 == 0:
                beautified[entry] = ""
                key = entry
            else:
                if key.startswith('b'):
                    # those entry are supposed to be in b64 but the padding was lost
                    missing_padding = len(entry) % 4
                    if missing_padding:
                        entry += '=' * (4 - missing_padding)
                beautified[key] = entry
        return beautified

    def beautify_headers(self, ugly_dict):
        """

            Process:
                Clean known headers if found in the dict

            Input:
                ugly_dict: a dict that contains eml headers and their values

            Output:
                A nice and clean dict
        """
        beautified_headers = {}
        for header in ugly_dict.keys():
            if not header.startswith("X"):
                # RFC822 headers or personalized entry in the dict
                if header.startswith("To") or header.startswith("From") :
                    try:
                        bad_chars = re.compile('[%s]' % '"')
                        raw = bad_chars.sub('', ugly_dict[header])
                        raw = filter(None, raw)
                        beautified_headers[header]=[]
                        for s in raw.split(">,"):
                            address=[]
                            for sub_s in s.split("<"):
                                bad_chars = re.compile('[%s]' % "'>")
                                sub_s = bad_chars.sub('', sub_s)
                                sub_s = re.sub("^[ ]",'',sub_s)
                                temp = decode_header(sub_s)
                                if temp[0][1] is not None:
                                    sub_s = temp[0][0].decode(temp[0][1], 'strict')
                                address.append(sub_s)
                            beautified_headers[header].append(address)
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("Subject") or header.startswith("Thread-Topic"):
                    # separate case from "From" because there's no '< >' to remove
                    try:
                        temp = decode_header(ugly_dict[header])
                        if temp[0][1] is not None:  # check if it's encoded
                            decoded = temp[0][0].decode(temp[0][1], 'strict')
                        else:
                            decoded = temp[0][0]
                        beautified_headers[header] = decoded
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("Message-ID") or \
                        header.startswith("Return-Path") or \
                        header.startswith("In-Reply-To") or \
                        header.startswith("References"):
                    try:
                        bad_chars = re.compile('[%s]' % '<>')
                        beautified_headers[header] = bad_chars.sub('', ugly_dict[header])
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("DKIM-Signature"):  # the DKIM-signature is a dict concatenate as a string
                    try:
                        beautified_headers[header] = self.beatify_dict(ugly_dict[header])
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("Authentication"):
                    # same as DKIM-signature but much simpler (or not...)
                    # TODO: find how this header is supposed to be arranged

                    try:
                        auth_res = ugly_dict[header].split(';')
                        beautified_headers[header] = []
                        for entry in auth_res:
                            start = re.search(r'[a-z]', entry).start()
                            beautified_headers[header].append(entry[start:])

                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("Content-Type"):
                    try:
                        content = ugly_dict[header].split(';')
                        beautified_headers[header] = {}
                        beautified_headers[header][header] = content[0]
                        if len(content) > 1:
                            boundary = content[1].replace(' ', '')
                # the boundary field can be boundary="----=_Part_39" the 2nd '=' being part of the boundary
                            beautified_headers[header]["boundary"] = boundary[9:].replace('\"', '')

                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("Sender"):
                    try:
                        bad_chars = re.compile('[%s]' % '<>')
                        beautified_headers[header] = bad_chars.sub('', ugly_dict[header])
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("Journaling_Information"):
                    #personalized entry with the journaling information
                    try:
                        beautified_headers[header] = {}
                        for key in ugly_dict[header].keys():
                            if key.startswith("Message-I"): # sometimes it's "Message-ID" and sometimes "Message-Id"
                                bad_chars = re.compile('[%s]' % '<>')
                                beautified_headers[header][key] = bad_chars.sub('', ugly_dict[header][key])
                            elif key.startswith("Recipient"):
                                beautified_headers[header][key] = []
                                for elem in ugly_dict[header][key]:
                                    working_dict=elem
                                    for entry in working_dict.keys():
                                        working_dict[entry]=working_dict[entry].replace('\r', '')

                                    beautified_headers[header][key].append(working_dict)
                            elif key.startswith("Subject") :
                                beautified_headers[header][key] = ugly_dict[header][key].decode('iso-8859-1').encode('utf8')

                            else:
                                beautified_headers[header][key] = ugly_dict[header][key].decode('iso-8859-1').encode('utf8')
                            
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("PhishMe_Information"):
                    try:
                        beautified_headers[header] = self.beautify_headers(ugly_dict[header])
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("ARC"):
                    if header.startswith("ARC-Message-Signature") \
                            or header.startswith("ARC-Seal"):
                        try:
                            beautified_headers[header] = self.beatify_dict(ugly_dict[header])
                        except Exception as e:
                            self.log.error(e)
                            beautified_headers[header] = ugly_dict[header]

                    elif header.startswith("ARC-Authentication-Results"):

                        try:
                            auth_res = ugly_dict[header].split(';')
                            beautified_headers[header] = []
                            for entry in auth_res:
                                start = re.search(r'[a-z]', entry).start()
                                beautified_headers[header].append(entry[start:])

                        except Exception as e:
                            self.log.error(e)
                            beautified_headers[header] = ugly_dict[header]
                    else:
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("email_headers"):
                    print "email_headers"
                    pprint.pprint(ugly_dict[header])
                    try:
                        beautified_headers[header] = {}
                        key=""
                        value=""
                        for s in filter(None,ugly_dict[header]):
                            if s.startswith(' '):
                                pprint.pprint(beautified_headers[header][key])
                                pprint.pprint(s.lstrip())
                                if key in beautified_headers[header].keys(): 
                                    beautified_headers[header][key][-1]=beautified_headers[header][key][-1]+" "+s.lstrip()
                                else:
                                    beautified_headers[header][key]=beautified_headers[header][key]+" "+s.lstrip()
                            else:
                                index = s.index(":")
                                print index
                                key = s[:index]
                                print key
                                print key.startswith(' ')
                                value = s[index + 2:]
                                if key in beautified_headers[header].keys():
                                    if not isinstance(beautified_headers[header][key], list):
                                        temp = beautified_headers[header][key]
                                        beautified_headers[header][key] = []
                                        beautified_headers[header][key].append(temp)
                                    beautified_headers[header][key].append(value)
                                    continue
                                beautified_headers[header][key] = value
                        beautified_headers[header] = self.beautify_headers(beautified_headers[header])
                    except Exception as e:
                        self.log.exception(e)
                        beautified_headers[header] = ugly_dict[header]
                elif header.startswith("received") or header.startswith("Received"):
                    try:
                        if isinstance(ugly_dict[header], list):
                            beautified_headers[header] = []
                            for s in ugly_dict[header]:
                                beautified_headers[header].append(s)
                        else:
                            beautified_headers[header] = ugly_dict[header]
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                else:
                    beautified_headers[header] = ugly_dict[header]
            else:  # all the non-rfc822 headers (client dependent)
                if header.startswith("X-YMail"):  # Yahoo mail headers
                    try:
                        bad_chars = re.compile('[%s]' % '\n\r\t ')
                        beautified_headers[header] = bad_chars.sub('', ugly_dict[header])
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("X-G"):  # GMail headers
                    try:
                        if "DKIM" in header:
                            beautified_headers[header] = self.beatify_dict(ugly_dict[header])
                        else:
                            beautified_headers[header] = ugly_dict[header]
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("X-Apparently-To"):
                    try:
                        apparently = ugly_dict[header].split(';')
                        beautified_headers[header] = (apparently[0], apparently[1][1:])
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]

                elif header.startswith("X-MS-Exchange-Parent-Message-Id"):  # Microsoft Exchange headers
                    try:
                        bad_chars = re.compile('[%s]' % '<>')
                        beautified_headers[header] = bad_chars.sub('', ugly_dict[header])
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]
                
                elif header.startswith("X-MS-Exchange-Forest-IndexAgent"):  # Microsoft Exchange headers
                    try:
                        bad_chars = re.compile('[%s]' % '\n\r\t /')
                        beautified_headers[header] = bad_chars.sub('', ugly_dict[header])
                    except Exception as e:
                        self.log.error(e)
                        beautified_headers[header] = ugly_dict[header]
                else:
                    beautified_headers[header] = ugly_dict[header]
        return beautified_headers
