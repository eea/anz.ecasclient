# python
import socket
from urllib2 import urlopen, URLError, HTTPError
from logging import getLogger

from anz.casclient.validationspecification import TicketValidator
from anz.casclient.exceptions import ConnectionException

LOG = getLogger( 'anz.casclient' )

def patchedRetrieveResponseFromServer( url ):
    ''' Contacts the CAS Server and retrieve the response.
    '''
    # Set the timeout to a higher value than the default in anz.casclient of 5
    socket.setdefaulttimeout( 15 )
    try:
        response = urlopen( url )
    except HTTPError, e:
        LOG.warning( e )
        raise ConnectionException( 'Error code: %s' % e.code )
    except URLError, e:
        LOG.warning( e )
        raise ConnectionException( 'Fail to connect, %s' % e.reason )
    except Exception, e:
        LOG.warning( e )
        raise
    
    return response.read()

def retrieveResponseFromServer( self, validationUrl, ticket ):
    ''' See interfaces.ITicketValidator. '''
    return patchedRetrieveResponseFromServer( validationUrl )

# Here we patch the TicketValidator's retrieveResponseFromServer method to call our patched function
TicketValidator.retrieveResponseFromServer = retrieveResponseFromServer
