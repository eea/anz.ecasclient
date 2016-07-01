from anz.casclient.validationspecification import Cas20ServiceTicketValidator
from anz.casclient.exceptions import InternalException
from xml.dom import minidom as minidom


class ECas20ServiceTicketValidator(Cas20ServiceTicketValidator):
    ''' This implements CE ECAS protocol based on anz.casclient
    There are some differences between a standard CAS implementation and
    the CE ECAS. Some simple as the cas namespace others more obscure.
    '''
    CAS_NS = 'https://ecas.ec.europa.eu/cas/schemas'

    def __init__(self, casServerUrlPrefix, casServerValidationUrl, pgtStorage, renew=None):
        self.casServerValidationUrl = casServerValidationUrl
        # maintain only one default
        if renew is None:
            super(ECas20ServiceTicketValidator, self).__init__(casServerUrlPrefix, pgtStorage)
        else:
            super(ECas20ServiceTicketValidator, self).__init__(casServerUrlPrefix, pgtStorage, renew)

    def getUrlSuffix( self ):
        return "laxValidate"

    def _constructValidationUrl(self, ticket, service, proxyCallbackUrl):
        """ eCAS uses a totally different url for validation.
        Rely mostly on parent class but take this difference into account."""
        saveUrl = self.casServerUrlPrefix
        self.casServerUrlPrefix = self.casServerValidationUrl
        url = super(ECas20ServiceTicketValidator, self)._constructValidationUrl(
            ticket, service, proxyCallbackUrl)
        self.casServerUrlPrefix = saveUrl
        return url


    def parseResponseFromServer(self, response):
        try:
            casPrincipalAs = super(ECas20ServiceTicketValidator, self).parseResponseFromServer(response)
        except InternalException as e:
            # anz.casclient was modified to throw a swallable exception now, so we never enter this.
            if 'ticket' in e.message and ' not recognized' in e.message:
                # this is one of the swallowable exceptions - so that authentication will continue with the next plugin
                raise TypeError('Not to be authenticated by this plugin')
            else:
                raise
        # ecas user tag does not contain the actual user
        dom = minidom.parseString(response)
        elements = dom.getElementsByTagNameNS(self.CAS_NS, 'moniker')
        userId = elements and elements[0].firstChild.data or None
        setattr(casPrincipalAs.principal, 'ecas_id', casPrincipalAs.principal.id)
        casPrincipalAs.principal.id = userId
        return casPrincipalAs
