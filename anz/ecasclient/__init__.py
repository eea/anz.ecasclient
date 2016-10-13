
# zope
from AccessControl.Permissions import manage_users as ManageUsers

# cmf
from Products.PluggableAuthService.PluggableAuthService import \
     registerMultiPlugin

from anz.ecasclient.ecasclient import AnzECASClient, \
     manage_addAnzECASClient, addAnzECASClientForm

from anz.ecasclient import patches
# register plugins with pas
try:
    registerMultiPlugin( AnzECASClient.meta_type )
except RuntimeError:
    # make refresh users happy
    pass

def initialize( context ):
    context.registerClass( AnzECASClient,
                           permission=ManageUsers,
                           constructors=( addAnzECASClientForm,
                                          manage_addAnzECASClient
                                          ),
                           icon='www/anz_ecasclient.png',
                           visibility=None
                           )

