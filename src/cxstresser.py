# -----------------------------------------------------------------------------
# Checkmarx intrumentation metrics for Prometheus
# Scan engine and queue usage monitoring
#
# TODO: Add https serving capability 
#       (SAST https client is already suported)
#       
# -----------------------------------------------------------------------------


# IMPORTS
try:
    import sys
    import os
    import json
    import requests
    import threading
    import time
    import datetime
    import collections
    import logging
except ImportError:
    print("Could not load needed modules, exiting...")
    sys.exit(65)




# ------------------------------------------------------------------
# General constants
# ------------------------------------------------------------------
__author__          = "Joao Costa"
__version__         = "1.0.0"
__date__            = "February 2020"
__maintainer__      = "Joao Costa"
__email__           = "joao.costa@checmarx.com"
__status__          = "Production"




# ------------------------------------------------------------------
# Global vars holding configurations
# ------------------------------------------------------------------
_hostname   = ""                    # SAST host endpoint for REST/SOAP, optionally with port
_username   = ""                    # SAST username, suitable for REST/SOAP usage
_password   = ""                    # SAST password, suitable for REST/SOAP usage 
_promport   = 9700                  # Prometheus listening port 
_loglevel   = 20                    # Log level (10=Debug, 20=Info, 30=Warning, 40=Error, 50=Critical)
_configfile = "configs.json"        # File name holding configurations
_logfile    = "cxpromstress.log"    # File name holding log entries (path is ./logs)


_concurrentscans    = 0
_scansrunning       = 0
_scansqueue         = 0
_stepmode           = 0 
_lastproject        = -1

# ------------------------------------------------------------------
# SAST Logon
# ------------------------------------------------------------------
# usage:    logon using REST api interface and obtain an authentication
#           token for subsequent REST calls
# hostname: can be the host or the ip address
#           can be prefixed with "http://" or "https://""
#           can be suffixed with a port number in the form ":port"
#           if not prefixed then http:// is assumed
# returns   on success the authentication bearer token usabled for future calls
#           on error an empty string
# ------------------------------------------------------------------
def cxlogon( hostname = "", username = "", password = "" ):
    logger = logging.getLogger('cxprometheus')    
    stoken  = ""
    sapipath = hostname.lower()
    if ( sapipath.startswith('http://') == False ) and ( sapipath.startswith('https://') == False ) :
        sapipath = "http://" + sapipath
    if ( sapipath.endswith( '/') ) :
        sapipath = sapipath + "cxrestapi/auth/identity/connect/token"
    else :
        sapipath = sapipath + "/cxrestapi/auth/identity/connect/token"
    shead   = { 'Content-Type':'application/x-www-form-urlencoded' }
    sbody   = { 'username':username,
                'password':password,
                'grant_type':'password',
                'scope':'sast_rest_api',
                'client_id':'resource_owner_client',
                'client_secret':'014DF517-39D1-4453-B7B3-9930C563627C' }
    logger.debug( "Logon at " + sapipath )
    try:
        # Post request to host, accepting self-signed certificates
        sresponse = requests.post( sapipath, data = sbody, headers = shead, verify = False )
        if (sresponse.status_code not in [200, 201, 202]):
            logger.error( "Logon response: " + str(sresponse.status_code) + ", " + sresponse.text )
            return ""
    except Exception as err:       
        # This is a critical failure as it is unable to talk to SAST
        serr = str(err)
        logger.critical( "Logon: " + serr ) 
        raise
    # Get token from returned data
    sjson = sresponse.json()
    skeykind = sjson["token_type"]
    if (skeykind == ""):
        skeykind = "Bearer"
    skeyval = sjson["access_token"]
    if (skeyval != "") :
        stoken = skeykind + ' ' + skeyval
    logger.debug( "Logon: " + skeykind + " token was retreieved successfully" )        
    return stoken 



# ------------------------------------------------------------------
# SAST projects
# ------------------------------------------------------------------
# usage:    retrieves the list of projects available using REST
#           usable form v8.6.0
# hostname: can be the host or the ip address
#           can be prefixed with "http://" or "https://""
#           can be suffixed with a port number in the form ":port"
#           if not prefixed then http:// is assumed
# apitoken: a valid Bearer token. (see: cxauthy.py)
#           when present, version will be retrieved via REST
#           call to engine servers information
# returns:  projects list
# ------------------------------------------------------------------
def cxgetprojects( hostname = "", apitoken = "" ):
    logger = logging.getLogger('cxprometheus')
    sapipath = hostname.lower()
    if ( sapipath.startswith('http://') == False ) and ( sapipath.startswith('https://') == False ) :
        sapipath = "http://" + sapipath
    if ( sapipath.endswith( '/') ) :
        sapipath = sapipath + "cxrestapi/projects"
    else :
        sapipath = sapipath + "/cxrestapi/projects"
    shead = {'Content-Type':'application/json', 'Authorization':apitoken }
    sbody = {}
    logger.debug( "Get projects at " + sapipath )
    try:
        # Get request to host, accepting self-signed certificates
        sresponse = requests.get( sapipath, data = sbody, headers = shead, verify = False )
        if (sresponse.status_code not in [200, 201, 202]):
            logger.error( "Get projects response: " + str(sresponse.status_code) + ", " + sresponse.text )
            return []
    except Exception as err:
        serr = str(err)
        logger.error( "Get projects: " + serr )
        raise
    # Process result json
    projects = json.loads(sresponse.content)
    res = []
    if (projects != []):    
        for project in projects:    
            for link in project["links"]:
                if link.get("type") == "git":
                    res.append( project["id"])
    if (res == []):
        logger.debug( "Get projects: no git projects found" )
    else:
        logger.debug( "Get projects: retrieved " + str(len(res)) + " git projects(s)" )
    return res




# ------------------------------------------------------------------
# SAST scans queue
# ------------------------------------------------------------------
# usage:    retrieves the scans queue list using REST
#           usable form v8.6.0, using either REST
# hostname: can be the host or the ip address
#           can be prefixed with "http://" or "https://""
#           can be suffixed with a port number in the form ":port"
#           if not prefixed then http:// is assumed
# apitoken: a valid Bearer token. (see: cxauthy.py)
#           when present, version will be retrieved via REST
#           call to engine servers information
# returns:  queue list
# ------------------------------------------------------------------
def cxgetscansqueue( hostname = "", apitoken = "" ):
    logger = logging.getLogger('cxprometheus')
    sapipath = hostname.lower()
    if ( sapipath.startswith('http://') == False ) and ( sapipath.startswith('https://') == False ) :
        sapipath = "http://" + sapipath
    if ( sapipath.endswith( '/') ) :
        sapipath = sapipath + "cxrestapi/sast/scansQueue"
    else :
        sapipath = sapipath + "/cxrestapi/sast/scansQueue"
    shead = {'Content-Type':'application/json', 'Authorization':apitoken }
    sbody = {}
    logger.debug( "Get scan queue at " + sapipath )
    try:
        # Get request to host, accepting self-signed certificates
        sresponse = requests.get( sapipath, data = sbody, headers = shead, verify = False )
        if (sresponse.status_code not in [200, 201, 202]):
            logger.error( "Get scan queue response: " + str(sresponse.status_code) + ", " + sresponse.text )
            return []
    except Exception as err:
        serr = str(err)
        logger.error( "Get scan queue: " + serr )
        raise
    # Process result json
    sscans = json.loads(sresponse.content)
    if (sscans == []):
        logger.debug( "Get scan queue: no scans found in queue" )
    else:
        logger.debug( "Get scan queue: retrieved " + str(len(sscans)) + " scan(s) in queue" )
    return sscans



# ------------------------------------------------------------------
# SAST engines
# ------------------------------------------------------------------
# usage:    retrieves the engine list using REST
#           usable form v8.6.0
# hostname: can be the host or the ip address
#           can be prefixed with "http://" or "https://""
#           can be suffixed with a port number in the form ":port"
#           if not prefixed then http:// is assumed
# apitoken: a valid Bearer token. (see: cxauthy.py)
#           when present, version will be retrieved via REST
#           call to engine servers information
# returns:  engines list
# ------------------------------------------------------------------
def cxgetengines( hostname = "", apitoken = "" ):
    logger = logging.getLogger('cxprometheus')
    sapipath = hostname.lower()
    if ( sapipath.startswith('http://') == False ) and ( sapipath.startswith('https://') == False ) :
        sapipath = "http://" + sapipath
    if ( sapipath.endswith( '/') ) :
        sapipath = sapipath + "cxrestapi/sast/engineServers"
    else :
        sapipath = sapipath + "/cxrestapi/sast/engineServers"
    shead = {'Content-Type':'application/json', 'Authorization':apitoken }
    sbody = {}
    logger.debug( "Get engines at " + sapipath )
    try:
        # Get request to host, accepting self-signed certificates
        sresponse = requests.get( sapipath, data = sbody, headers = shead, verify = False )
        if (sresponse.status_code not in [200, 201, 202]):
            logger.error( "Get engines response: " + str(sresponse.status_code) + ", " + sresponse.text )
            return []
    except Exception as err:
        serr = str(err)
        logger.error( "Get engines: " + serr )
        raise
    # Process result json
    engines = json.loads(sresponse.content)
    if (engines == []):
        logger.debug( "Get engines: no engines found" )
    else:
        logger.debug( "Get engines: retrieved " + str(len(engines)) + " engine(s)" )
    return engines



# ------------------------------------------------------------------
# SAST scans queue count
# ------------------------------------------------------------------
# usage:    retrieves the scans queue list using REST
#           usable form v8.6.0, using either REST
# hostname: can be the host or the ip address
#           can be prefixed with "http://" or "https://""
#           can be suffixed with a port number in the form ":port"
#           if not prefixed then http:// is assumed
# apitoken: a valid Bearer token. (see: cxauthy.py)
#           when present, version will be retrieved via REST
#           call to engine servers information
# returns:  queue count
# ------------------------------------------------------------------
def cxgetscansqueuecount( hostname = "", apitoken = "" ):
    sscans = cxgetscansqueue( hostname, apitoken )
    if (sscans == []):
        return 0
    else:
        return len(sscans)



# ------------------------------------------------------------------
# SAST scans queue count
# ------------------------------------------------------------------
# usage:    retrieves the scans queue list using REST
#           usable form v8.6.0, using either REST
# hostname: can be the host or the ip address
#           can be prefixed with "http://" or "https://""
#           can be suffixed with a port number in the form ":port"
#           if not prefixed then http:// is assumed
# apitoken: a valid Bearer token. (see: cxauthy.py)
#           when present, version will be retrieved via REST
#           call to engine servers information
# returns:  scan count
# ------------------------------------------------------------------
def cxgetscansrunningcount( hostname = "", apitoken = "" ):
    sscans = cxgetscansqueue( hostname, apitoken )
    count = 0
    if (sscans == []):
        return 0
    else:
        for sscan in sscans:
            scanstatusid    = sscan["stage"]["id"] 
            if (scanstatusid >= 4) and (scanstatusid <= 6):   # Scanning
                count = count + 1
    return count




def cxstartscan( hostname = "", apitoken = "", projectid = 0 ):
    if (projectid == 0):
        return

    logger = logging.getLogger('cxprometheus')
    sapipath = hostname.lower()
    if ( sapipath.startswith('http://') == False ) and ( sapipath.startswith('https://') == False ) :
        sapipath = "http://" + sapipath
    if ( sapipath.endswith( '/') ) :
        sapipath = sapipath + "cxrestapi/sast/scans"
    else :
        sapipath = sapipath + "/cxrestapi/sast/scans"
    #shead = {'Content-Type':'application/json', 'Authorization':apitoken }
    #sbody = {}
    shead = {'Content-Type':'application/x-www-form-urlencoded', 'Authorization':apitoken }

    sbody = { 'projectId':projectid, 'isIncremental':'false', 'isPublic':'true', 'forceScan':'true', 'comment':'trigger'}


    logger.debug( "Get engines at " + sapipath )
    try:
        # Get request to host, accepting self-signed certificates
        sresponse = requests.post( sapipath, data = sbody, headers = shead, verify = False )
        if (sresponse.status_code not in [200, 201, 202]):
            logger.error( "Start scan response: " + str(sresponse.status_code) + ", " + sresponse.text )
            return []
    except Exception as err:
        serr = str(err)
        logger.error( "Start scan: " + serr )
        raise
    # Process result json
    scan = json.loads(sresponse.content)
    return scan




# ------------------------------------------------------------------
# SAST scans queue count
# ------------------------------------------------------------------
# usage:    retrieves the scans queue list using REST
#           usable form v8.6.0, using either REST
# hostname: can be the host or the ip address
#           can be prefixed with "http://" or "https://""
#           can be suffixed with a port number in the form ":port"
#           if not prefixed then http:// is assumed
# apitoken: a valid Bearer token. (see: cxauthy.py)
#           when present, version will be retrieved via REST
#           call to engine servers information
# returns:  scan count
# ------------------------------------------------------------------
def cxgetenginecaps( hostname = "", apitoken = "" ):
    sengines = cxgetengines( hostname, apitoken )
    concurrent = 0
    for sengine in sengines:
        escans     = sengine["maxScans"]
        concurrent = concurrent + escans
    return concurrent



# ------------------------------------------------------------------
# Common configurations on external json file
# ------------------------------------------------------------------
# filename: the file where the configurations are stored
#           see const_configs for default
# returns   success true or false
# ------------------------------------------------------------------
def loadconfigurations():
    global _promport
    global _hostname
    global _username
    global _password
    global _loglevel

    # Configurations file
    if (os.path.exists(_configfile)):
        fp = open(_configfile, 'r')
        try:
            sdict = json.load(fp)
            _hostname = sdict.get('hostname', '')
            _username = sdict.get('username', '')
            _password = sdict.get('password', '' )
            _promport = sdict.get('promport', 9700)
            _loglevel = sdict.get('loglevel', 20)
        finally:
            fp.close()

    # Pre-process log level
    if (_loglevel <= 0):
        _loglevel = 100                     # Out of scope, no logs
    elif (_loglevel <= logging.DEBUG):      
        _loglevel = logging.DEBUG           # 10
    elif (_loglevel <= logging.INFO):
        _loglevel = logging.INFO            # 20
    elif (_loglevel <= logging.WARNING):
        _loglevel = logging.WARNING         # 30
    elif (_loglevel <= logging.ERROR):
        _loglevel = logging.ERROR           # 40
    elif (_loglevel <= logging.CRITICAL):
        _loglevel = logging.CRITICAL        # 50
    else:
        _loglevel = 100                     # Out of scope, no logs

    # Check log folder
    if (os.path.exists('logs')):
        if (not os.path.isdir('logs')):
            os.mkdir('logs')
    else:
        os.mkdir('logs')
    logfilename = 'logs' + os.path.sep + _logfile

    # Init log file and format
    logger = logging.getLogger('cxprometheus')
    #logger.setLevel(logging.INFO)
    logger.setLevel(_loglevel)
    # create a file handler
    handler = logging.FileHandler(logfilename)
    handler.setLevel(_loglevel)
    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    # add the file handler to the logger
    logger.addHandler(handler)

    _errors = list()
    # Check configurations
    if (_hostname == ""):
        _errors.append( "Missing SAST host name in configuration (hostname)" )
    if (_username == ""):
        _errors.append( "Missing SAST user name in configuration (username)" )
    if (_password == ""):
        _errors.append( "Missing SAST user credentials in configuration (password)" )
    if (_promport <= 0):
        _errors.append( "Missing prometheus exporter port in configuration (promport)" )
    # Passed :)
    if (_errors == []):
        logger.info( "Service started, listening on port " + str(_promport) )
        return True
    else:
        logger.info( "Unable to start, configurations missing" )
        for _error in _errors:
            logger.critical( _error )
        return False




# ------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------
# Just writes closure to log
# ------------------------------------------------------------------
def cleanup():
    logger = logging.getLogger('cxprometheus')
    logger.info( "Service stoped" )



# ------------------------------------------------------------------
# Compute cargo
# ------------------------------------------------------------------
# 
# ------------------------------------------------------------------
def computecargo( hostname = "", apitoken = "" ):
    global _concurrentscans
    global _scansrunning
    global _scansqueue
    global _stepmode

    # Evaluate number of concurrent scans capability
    _concurrentscans    = cxgetenginecaps( hostname, apitoken )
    # Determine the number of scans running
    _scansrunning       = cxgetscansrunningcount( hostname, apitoken )
    # Determine the number of scans in queue, running or not
    _scansqueue         = cxgetscansqueuecount( hostname, apitoken )
    
    
    scanstostart = 0
    if (_stepmode == 0):
        # Put 3 times the capacity in the queue
        scanstostart = (_concurrentscans * 3) - (_scansqueue)
    else:
        scanstostart = (_concurrentscans) - (_scansqueue)

    if (scanstostart < 0):
        scanstostart = 0

    _stepmode = _stepmode + 1
    if (_stepmode > 10):
        _stepmode = 0

    return scanstostart


def startscans(hostname = "", apitoken = "", scanstostart = 0 ):
    global _lastproject

    logger = logging.getLogger('cxprometheus')

    if (scanstostart <= 0):
        return

    sprojects = cxgetprojects( hostname, apitoken )

    prjcount = len(sprojects)

    counter = scanstostart

    logger.info( "Starting " + str(scanstostart) + " new scans" )
    
    while( counter > 0):
        _lastproject = _lastproject + 1
        if (_lastproject >= prjcount):
            _lastproject = 0
        projectid = sprojects[_lastproject]

        cxstartscan( _hostname, stoken, projectid )

        counter = counter - 1




if __name__ == '__main__':

    # Load and check configurations
    if (loadconfigurations() == False):
        sys.exit(70)

 #   stoken = cxlogon( _hostname, "prometheus", "Cx123456!")

#    cxstartscan( _hostname, stoken, 3 )


    try:

        while (True):

            #stoken = cxlogon( _hostname, _username, _password)
            stoken = cxlogon( _hostname, "prometheus", "Cx123456!")

            scanstostart = computecargo( _hostname, stoken )

            if (scanstostart > 0):
                startscans( _hostname, stoken, scanstostart )

            time.sleep(60)      # Wait a minute

    finally:
        # Log finish
        cleanup()

