from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, constants
import email
from email.header import decode_header
import re
#from lxml import html, etree
import tempfile
import quopri
#import base64



class EmlParser(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'document/email'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_ENABLED = True
    SERVICE_STAGE = 'EXTRACT'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256
    named_attachments_only = False
    max_attachment_size = 10737418240


    def __init__(self, cfg=None):
        super(EmlParser, self).__init__(cfg)
    
    def execute(self, request):
        """Main module"""
        print "start"
        result = Result()
        local = request.download()
        found = {}



        with open(local,"r") as fh:
            message = email.message_from_file(fh)
        

        found = self.extract_info(message)
        #test=self.extract_from_attachement(message)
        """
        for file in test:
            request.add_extracted(*file)
        """
        
        section = ResultSection(score=SCORE.NULL,title_text= "Extracted informations",body_format='JSON',body=found)
        
        result.add_section(section)

        request.result = result


    def extract_from_attachement(self,msg):
        """Iterate through the eml to extract atached emls and extract their informations

            Args:
            msg: an email.message.Message

            Returns:
            A dict containing the information gathered from the attachements (empty is no eml attached)
        """
        found_eml = False

        i=1
        attachement_info={}
        attachements=[]

        for part in msg.walk():

            print part.get_content_type()
            print part.get("Content-Disposition", "")
            if part.get_content_type() == 'message/rfc822':
                found_eml = True
                p_name = part.get_filename(None)
                #p_load = part.get_payload()
                #print "---------------"
                #print "p_load dans if dans for"
                #print p_load

            elif  found_eml and part.get_content_type() == 'text/plain':
                ft = tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False)

                ft.write(part.get_payload().decode('base64','strict'))

                name = ft.name

                ft.close()
                attachements.append((name, part.get_content_type(), p_name, self.SERVICE_CLASSIFICATION, ))
                new_eml_str = part.get_payload().decode('base64','strict')
                
                new_eml = email.message_from_string(new_eml_str)

                attachement_info['attachement'+`i`]=self.extract_info(new_eml)
                attachement_info['attachement'+`i`]['attachement']=self.extract_from_attachement(new_eml)
                if not len(attachement_info['attachement'+`i`]['attachement']) > 0:
                    attachement_info['attachement'+`i`].pop('attachement') 
                i += 1

        return attachements


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
            if key =='From' or key == 'To':
                info[key]=decode_header(msg.get(key))
            else:
                info[key]=bad_chars.sub('',msg.get(key))
            

        """Attempt to extract addresses from the body in case it's  a forwarded email"""
        """ Remove the text/html part"""
        """
        str_load = str(msg.get_payload()[0])
        pos = str_load.find("text/html")
        if pos >-1: 
            body_plain= str_load[:pos] 
        else:
            body_plain= str_load
           
        addresses = re.findall(r'[\w\.-=\n\r]+@[\w\.-]+\.\w+', body_plain,re.MULTILINE)
        
        bad_chars = re.compile('[%s]' % '\t\n\r<=')
        for i,address in enumerate(addresses):
            addresses[i] = bad_chars.sub('',address)
            #temp= ":".join("{:02x}".format(ord(c)) for c in addresses[i])
        if addresses: 

            addresses = list(set(addresses))
            info['Addresses_Body'] = addresses 
        """
        return info