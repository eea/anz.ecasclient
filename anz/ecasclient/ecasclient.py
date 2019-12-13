import re
import urllib2
from logging import getLogger

from AccessControl import ClassSecurityInfo, getSecurityManager
from anz.casclient.casclient import AnzCASClient
# original CAS imports
from anz.casclient.interfaces import IAnzCASClient
from anz.casclient.validationspecification import (Cas10TicketValidator,
                                                   Cas20ProxyTicketValidator)
from Globals import InitializeClass
from persistent import Persistent
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import (
    IAuthenticationPlugin, IChallengePlugin, ICredentialsResetPlugin,
    ICredentialsUpdatePlugin, IExtractionPlugin)
from Products.PluggableAuthService.utils import classImplements
from Products.Reportek.constants import ECAS_ID, ENGINE_ID
# eCAS imports
from validationspecification import ECas20ServiceTicketValidator
from ZODB.PersistentMapping import PersistentMapping
# zope imports
from zope.interface import implements

LOG = getLogger( 'anz.ecasclient' )

addAnzECASClientForm = PageTemplateFile(
    'www/add_anzcasclient_form.pt', globals() )

def manage_addAnzECASClient( self, id, title=None, REQUEST=None ):
    ''' Add an instance of anz ecas client to PAS. '''
    obj = AnzECASClient( id, title )
    self._setObject( obj.getId(), obj )

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(
            '%s/manage_workspace'
            '?manage_tabs_message='
            'AnzCentralAuthService+added.'
            % self.absolute_url()
            )


def isEmail(value):
    """ Return True if the value is a valid email
    """
    if re.match('^[^@]+@[^@]+\.[^@]+', value):
        return True


class EcasClient(Persistent):
    """ Ecas_id to username, email mapping
    """
    def __init__(self, ecas_id, value):
        self.ecas_id = ecas_id

        if isEmail(value):
            self._email = value
        else:
            self._username = value

    @property
    def username(self):
        return getattr(self, '_username', None)

    @property
    def email(self):
        return getattr(self, '_email', None)

class AnzECASClient(AnzCASClient):
    ''' Anz eCAS client extends anz.casclient to support European Council CAS'''

    implements( IAnzCASClient )

    meta_type = 'Anz eCAS Client'

    casServerValidationUrl = ''
    internalMapping = True

    security = ClassSecurityInfo()

    # Session variable use to save assertion
    CAS_ASSERTION = '__ecas_assertion'

    _properties = AnzCASClient._properties + (
        {
            'id': 'casServerValidationUrl',
            'label': 'eCAS Server Validation URL',
            'type': 'string',
            'mode': 'w'
        },
        {
            'id': 'internalMapping',
            'label': 'Use internal mapping for usernames',
            'type': 'boolean',
            'mode': 'w'
        }
    )

    def __init__( self, id, title ):
        super(AnzECASClient, self).__init__(id, title)
        self._ecas_id = PersistentMapping()

    def getEcasUserId(self, username):
        userdb = getattr(self, '_ecas_id', None)
        if userdb and self.internalMapping:
            for ecas_id, user in self._ecas_id.iteritems():
                if isEmail(username):
                    if user.email and user.email.lower() == username.lower():
                        return ecas_id
                else:
                    if user.username == username:
                        return ecas_id
        else:
            try:
                assertion = self.getAssertionFromSession()
                ecas_id = assertion.principal.ecas_id
                return ecas_id
            except Exception:
                pass
        return username

    def getEcasIDUser(self, ecas_id):
        """Return internal user mapping for the ecas_id.
        """
        userdb = getattr(self, '_ecas_id', {})
        return userdb.get(ecas_id)

    def getEcasIDEmail(self, ecas_id):
        """Return ecas user's email."""
        if self.internalMapping:
            ecas_user = self.getEcasIDUser(ecas_id)
            if ecas_user:
                return ecas_user.email
        else:
            # We cannot retrieve the user's email if we don't use the mapping
            return "Internal ECAS mapping disabled"

    def getEcasIDUsername(self, ecas_id):
        """Return ecas user's username."""
        ecas_user = self.getEcasIDUser(ecas_id)
        if ecas_user:
            return ecas_user.username

    security.declarePrivate( 'challenge' )
    def challenge( self, request, response, **kw ):
        if request['QUERY_STRING']:
            url = request['ACTUAL_URL'] + "?" + request['QUERY_STRING']
        else:
            url = request['ACTUAL_URL']
        came_from = urllib2.quote(url)
        response.setCookie('challenged', True, path='/')
        response.redirect( '/Login/unauthorized?came_from=%s' % came_from, lock=1 )
        return 1

    def validateServiceTicket(self, service, ticket):
        if self.ticketValidationSpecification == 'CAS 1.0':
            validator = Cas10TicketValidator(
            self.casServerUrlPrefix, self.renew )
        else:
            if self.acceptAnyProxy or self.allowedProxyChains:
                validator = Cas20ProxyTicketValidator(
                    self.casServerUrlPrefix,
                    self._pgtStorage,
                    acceptAnyProxy=self.acceptAnyProxy,
                    allowedProxyChains=self.allowedProxyChains,
                    renew=self.renew )
            else:
                validator = ECas20ServiceTicketValidator(
                    self.casServerUrlPrefix, self.casServerValidationUrl, self._pgtStorage, self.renew )
        return validator.validate(ticket, service, self.getProxyCallbackUrl() )

    security.declarePrivate( 'authenticateCredentials' )
    def authenticateCredentials( self, credentials ):
        user_and_info = super(AnzECASClient, self).authenticateCredentials(credentials)
        if not user_and_info:
            return None
        user, info = user_and_info
        """
        # this code should not be here, but in an assignLocalRolesPlugin
        # make sure the code following will not start a transaction without committing this one
        # else we shall loose the session stored by casclient.py:extractCredentials
        # and the next auth plugin will try to validate the ticket himself and fail
        # because this one was provided by a different sso service than what the next plugin is bound to
        try:
            engine = self.unrestrictedTraverse('/ReportekEngine')
            authMiddleware = engine.authMiddlewareApi
            if authMiddleware:
                authMiddleware.updateLocalRoles(user)
            #from Products.Reportek.BdrAuthorizationMiddleware import updateLocalRoles2
            #updateLocalRoles2(user)
        # make sure any relavant exception are caught before this point.
        # We wouldn't know what to do with them here...
        except:
            LOG.warning("Error while contacting Satelite Registry for authorization info. "
                        "Using the know roles assignments")
        """
        return user, info

    def invalidateOlderMapping(self, c_ecas_id, username):
        """Invalidate older mapping."""
        userdb = getattr(self, '_ecas_id', None)
        res = []
        if userdb:
            for ecas_id, user in self._ecas_id.iteritems():
                if ecas_id != c_ecas_id:
                    if isEmail(username):
                        if user.email and user.email.lower() == username.lower():
                            user._email = None
                            res.append(ecas_id)
                    else:
                        if user.username == username:
                            user._username = None
                            res.append(ecas_id)
        return res

    def mapUser(self, ecas, ecas_id, username):
        ecas_user = ecas._ecas_id.get(ecas_id)
        if not ecas_user:
            ecas_user = EcasClient(ecas_id, username)
            ecas._ecas_id[ecas_id] = ecas_user
            res = self.invalidateOlderMapping(ecas_id, username)
            if res:
                LOG.debug("Invalidated data for ecas id: {}".format(res))
        elif not ecas_user.email and isEmail(username):
            ecas_user._email = username
        elif isEmail(username) and ecas_user.email != username:
            ecas_user._email = username
        elif not ecas_user.username and not isEmail(username):
            ecas_user._username = username
        else:
            LOG.debug("User %s already mapped in %s app" % (username, ECAS_ID))

    def getAssertionFromSession(self):
        sdm = getattr( self, 'session_data_manager', None )
        assert sdm is not None, 'No session data manager found!'
        session = sdm.getSessionData( create=0 )
        assertion = self.getAssertion( session )

        return assertion

    def extractCredentials(self, request):
        creds = super(AnzECASClient, self).extractCredentials(request)
        assertion = self.getAssertionFromSession()

        if assertion and self.internalMapping:
            try:
                ecas = self.unrestrictedTraverse('/'+ENGINE_ID+'/acl_users/'+ECAS_ID)
                username = assertion.principal.id
                ecas_id = assertion.principal.ecas_id

                if not hasattr(ecas, '_ecas_id'):
                    ecas._ecas_id = PersistentMapping()
                    old_mapping = getattr(ecas, '_user2ecas_id', None)
                    if old_mapping:
                        for user, ecas_user_id in old_mapping.iteritems():
                            self.mapUser(ecas, ecas_user_id, user)
                        del ecas._user2ecas_id

                self.mapUser(ecas, ecas_id, username)

            except Exception as e:
                LOG.warning("Error getting username: {}".format(str(e)))
        return creds

classImplements(AnzCASClient,
                 IExtractionPlugin,
                 IChallengePlugin,
                 ICredentialsResetPlugin,
                 IAuthenticationPlugin)

InitializeClass( AnzCASClient )
