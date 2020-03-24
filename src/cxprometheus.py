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
    from prometheus_client.core import GaugeMetricFamily, REGISTRY
    from prometheus_client import start_http_server, CollectorRegistry
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
_loglevel   = 0                     # Log level (0=Minimum, 1=Complete, 2=Debug)
_configfile = "configs.json"        # File name holding configurations
_logfile    = "cxprometheus.log"    # File name holding log entries (path is ./logs)




# ------------------------------------------------------------------
# Local vars for metrics 
# ------------------------------------------------------------------
# Engine metric gauge
# Value is the number of scans
_metric1_name       = "checkmarx_sast_engines"
_metric1_desc       = "Checkmarx sast engines workload"
_metric1_labels     = [ "engineId", "engineName", "engineScan", "status" ]

# Queue duration metric gauge
# Value is duration in minutes
_metricx_labels     = [ "scanId", "engineId", "engineName", "locMin", "locMax" ]

_metric2_name       = "checkmarx_sast_scans_pulling"
_metric2_desc       = "Checkmarx sast scans pulling workload in minutes"

_metric3_name       = "checkmarx_sast_scans_queued"
_metric3_desc       = "Checkmarx sast scans queued workload in minutes"

_metric4_name       = "checkmarx_sast_scans_scanning"
_metric4_desc       = "Checkmarx sast scans scanning workload in minutes"

_metric5_name       = "checkmarx_sast_scans_full"
_metric5_desc       = "Checkmarx sast scans full workload in minutes"




# ------------------------------------------------------------------
# Local vars for authentication token thread sharing management
# ------------------------------------------------------------------
_token      = ""                # token
_tokenread  = 0                 # timestamp the token was last read
_tokenlock  = threading.Lock()  # threading




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
# The checkmarx collector class
# ------------------------------------------------------------------
class CxCollector(object):

    def __init__(self):
        logger = logging.getLogger('cxprometheus')
        logger.debug( "CxCollector: creating new instance (__init__)" )
        self.enginelist = collections.OrderedDict()
        # The metrics
        logger.debug( "CxCollector: creating metric " + _metric1_name )
        self._metric1 = GaugeMetricFamily( _metric1_name, _metric1_desc, labels=_metric1_labels )
        logger.debug( "CxCollector: creating metric " + _metric2_name )
        self._metric2 = GaugeMetricFamily( _metric2_name, _metric2_desc, labels=_metricx_labels )
        logger.debug( "CxCollector: creating metric " + _metric3_name )
        self._metric3 = GaugeMetricFamily( _metric3_name, _metric3_desc, labels=_metricx_labels )
        logger.debug( "CxCollector: creating metric " + _metric4_name )
        self._metric4 = GaugeMetricFamily( _metric4_name, _metric4_desc, labels=_metricx_labels )
        logger.debug( "CxCollector: creating metric " + _metric5_name )
        self._metric5 = GaugeMetricFamily( _metric5_name, _metric5_desc, labels=_metricx_labels )


    def gettoken(self):
        # If the token being used is older than 23.3 hours than get a new one
        global _token, _tokenread, _tokenlock
        logger = logging.getLogger('cxprometheus')
        logger.debug( "CxCollector: running internal gettoken" )
        _tokenlock.acquire()
        try:
            if (_token == "") or (_tokenread == 0) or (time.time() - _tokenread > 1400):
                if (_token == "") or (_tokenread == 0):
                    logger.debug( "CxCollector: token is null, calling logon" )
                elif (time.time() - _tokenread > 1400):
                    logger.debug( "CxCollector: token is too old, calling logon" )
                _token = cxlogon( _hostname, _username, _password)
                if (_token != ""):
                    _tokenread = time.time()
        finally:
            _tokenlock.release()
        return _token

    def resettoken(self):
        global _token, _tokenread, _tokenlock
        logger = logging.getLogger('cxprometheus')
        logger.debug( "CxCollector: running internal resettoken" )
        _tokenlock.acquire()
        try:
            _token = ""
            _tokenread = 0
        finally:
            _tokenlock.release()

    def setenginescan(self, scanid, engineid, scanstatus):
        logger = logging.getLogger('cxprometheus')
        logger.debug( "CxCollector: running internal setenginescan" )
        lfound = False
        for iengine in self.enginelist.values():
            if (iengine[0] == engineid) and (iengine[6] == scanid):
                iengine[7] = scanstatus
                lfound = True
                break
        if (not lfound):
            for iengine in self.enginelist.values():
                if (iengine[0] == engineid) and (iengine[6] == 0):
                    iengine[6] = scanid
                    iengine[7] = scanstatus
                    break

    def processdatestring( self, thedate ):
        if (type(thedate) == str):
            if ( "." in thedate ):
                return thedate
            else:
                return thedate + ".0"
        else:
            return thedate

    def describe(self):
        logger = logging.getLogger('cxprometheus')
        logger.debug( "CxCollector: running describe" ) 
        # The metrics...
        metric1 = self._metric1
        metric2 = self._metric2
        metric3 = self._metric3
        metric4 = self._metric4
        metric5 = self._metric5
        # Yield the metrics
        yield metric1
        yield metric2
        yield metric3        
        yield metric4
        yield metric5
              
    def collect(self):
        logger = logging.getLogger('cxprometheus')
        logger.debug( "CxCollector: running collect" )
        # The metrics...
        metric1 = self._metric1
        metric2 = self._metric2
        metric3 = self._metric3
        metric4 = self._metric4
        metric5 = self._metric5
        # Grant metrics are clear ...
        logger.debug( "CxCollector: clear metrics contents" )
        metric1.samples.clear()
        metric2.samples.clear()
        metric3.samples.clear()
        metric4.samples.clear()
        metric5.samples.clear()

        # Get authentication token or generate a new one if needed (token shall be valid for 24 hours)
        apitoken = self.gettoken()

        # Get engines 
        try:
            engines = cxgetengines( _hostname, apitoken )
        except:
            engines = []            
        # If no engines returned, recheck authorizations
        if (engines == []):
            self.resettoken()
            apitoken = self.gettoken()
            engines = cxgetengines( _hostname, apitoken )

        if (engines == []):
            logging.error( "CxCollector: no engines found to process" )

        # Get scans queue
        scans = cxgetscansqueue( _hostname, apitoken )

        # fp = open( 'data\scans1.txt', 'r')
        # try:
        #     scans = json.load(fp)            
        # finally:
        #     fp.close()

        # ----------------------------------------------------------------------------------
        # Process engines metrics, by relating engines to scans
        # Uses the dictionary "enginelist" to cache engine states
        # ----------------------------------------------------------------------------------

        logger.debug( "CxCollector: process engines" )
        # Remove form engines list cache any engine no longer found
        idx = len(self.enginelist.keys()) - 1
        while idx >= 0:
            ikeys   = self.enginelist.keys()
            iengx   = list(ikeys)[idx]
            iids    = iengx.split("_")
            lfound  = False
            for engine in engines:
                if (engine["id"] == int(iids[0])):
                    if (engine["maxScans"] >= int(iids[1])):
                        lfound = True
                        break
            if (lfound == False):
                self.enginelist.pop(iengx)
            idx = idx - 1
        # Add to engines list cache any new engines and found
        for engine in engines:
            idx = 1
            imax = engine["maxScans"]
            while idx <= imax:
                iengx = str(engine["id"]) + "_" + str(idx)
                if iengx not in (self.enginelist.keys()):
                    eid         = engine["id"]              # 0
                    ename       = str(engine["name"])       # 1
                    econc       = idx                       # 2
                    escans      = str(engine["maxScans"])   # 3
                    eminloc     = str(engine["minLoc"])     # 4
                    emaxloc     = str(engine["maxLoc"])     # 5
                    escanid     = 0                         # 6
                    estate      = "Idle"                    # 7
                    self.enginelist[iengx] = [ eid, ename, econc, escans, eminloc, emaxloc, escanid, estate ]                    
                idx = idx + 1

        logger.debug( "CxCollector: check scans assigned to engines and detect concurent ones" )
        # Remove from engines any scans finished or no longer found 
        for iengine in self.enginelist.values():
            scanid = iengine[6]
            lfound = False
            for scan in scans:
                if (scanid == scan["id"]):
                    # 1=New, 2=PreScan, 3=Queued, 4=Scanning, 6=PostScan, 7=Finished, 8=Canceled, 9=Failed, 10=SourcePullingAndDeployment or 1001=None. 
                    scanstatusid = scan["stage"]["id"]
                    if (scanstatusid >= 3) and (scanstatusid <= 6):
                        scanengine  = scan["engine"]
                        if (scanengine != None):
                            scanengineid = scanengine["id"]
                        else:
                            scanengineid = 0
                        if (scanengineid == iengine[0]):
                            lfound = True
            if (lfound == False):
                iengine[6] = 0
                iengine[7] = "Idle"
        # Add or update any new or updated scans into engines
        for scan in scans:
            scanid      = scan["id"]
            scanengine  = scan["engine"]
            if (scanengine != None):
                scanengineid = scanengine["id"]
            else:
                scanengineid = 0
            if (scanid > 0) and (scanengineid > 0):
                scanstatusid = scan["stage"]["id"]
                # 1=New, 2=PreScan, 3=Queued, 4=Scanning, 6=PostScan, 7=Finished, 8=Canceled, 9=Failed, 10=SourcePullingAndDeployment or 1001=None. 
                # Resolve duration according to statuses
                if (scanstatusid == 3 ):                                # Queued
                    scanenginestatus  = "Queued"
                elif (scanstatusid >= 4 ) and (scanstatusid <= 6 ):     # Scanning/postscan
                    scanenginestatus  = "Scanning"
                else:                                                   # No engine assigned here
                    scanenginestatus  = "Idle"                          
                # Register in cache
                if (scanenginestatus != "Idle"):
                    self.setenginescan(scanid, scanengineid, scanenginestatus)

        logger.debug( "CxCollector: process engine metrics" )
        # Present metrics for engines (metric1)
        for iengine in self.enginelist.values():
            if (iengine[7] == "Idle"):
                vvalue = 0
            else:
                vvalue = 1
            metric1.add_metric( [ str(iengine[0]), iengine[1], str(iengine[2]), iengine[7] ], vvalue )

        # ----------------------------------------------------------------------------------
        # Process scans queue metrics, for durations
        # ----------------------------------------------------------------------------------
        logger.debug( "CxCollector: process scans in queue and process metrics" )
        for scan in scans:
            scanid          = scan["id"]
            scanstatusid    = scan["stage"]["id"]           
            # Resolve engine details, if engine is available
            scanengineid        = "0"
            scanenginename      = ""
            scanenginelocmin    = "0"
            scanenginelocmax    = "999999999"
            scanengine      = scan["engine"]
            if (scanengine != None):
                for engine in engines:
                    if (engine["id"] == scanengine["id"]):
                        scanengineid        = str(engine["id"])
                        scanenginename      = str(engine["name"])
                        scanenginelocmin    = str(engine["minLoc"])
                        scanenginelocmax    = str(engine["maxLoc"])
                        break
            # 1=New, 2=PreScan, 3=Queued, 4=Scanning, 6=PostScan, 7=Finished, 8=Canceled, 9=Failed, 10=SourcePullingAndDeployment or 1001=None. 
            # Resolve duration according to statuses
            val_time        = float(0.0)
            scannew = datetime.datetime.strptime( self.processdatestring(scan["dateCreated"]), "%Y-%m-%dT%H:%M:%S.%f" ).timestamp()
            scannow = time.time()
            # The global metrics
            if (scanstatusid == 10) or (scanstatusid >= 1 and scanstatusid <= 6): # Full
                val_time = ( scannow - scannew ) / 60
                metric5.add_metric( [ str(scanid), scanengineid, scanenginename, scanenginelocmin, scanenginelocmax ], val_time )
            # Process according to status
            if (scanstatusid in [1, 2, 10 ]):                   # Pulling
                val_time = ( scannow - scannew ) / 60
                metric2.add_metric( [ str(scanid), scanengineid, scanenginename, scanenginelocmin, scanenginelocmax ], val_time )
            elif (scanstatusid == 3):                           # Queued
                try:
                    scanini = datetime.datetime.strptime( self.processdatestring(scan["queuedOn"]), "%Y-%m-%dT%H:%M:%S.%f" ).timestamp()
                except:
                    scanini = 0.0
                if (scanini > 0.0):
                    val_time = ( scannow - scanini ) / 60
                    metric3.add_metric( [ str(scanid), scanengineid, scanenginename, scanenginelocmin, scanenginelocmax ], val_time )
            elif (scanstatusid >= 4) and (scanstatusid <= 6):   # Scanning
                try:
                    scanini = datetime.datetime.strptime( self.processdatestring(scan["engineStartedOn"]), "%Y-%m-%dT%H:%M:%S.%f" ).timestamp()
                except:
                    scanini = 0.0
                if (scanini > 0.0):
                    try:
                        scanend = datetime.datetime.strptime( self.processdatestring(scan["completedOn"]), "%Y-%m-%dT%H:%M:%S.%f" ).timestamp()
                    except:
                        scanend = scannow
                    val_time = ( scanend - scanini ) / 60
                    metric4.add_metric( [ str(scanid), scanengineid, scanenginename, scanenginelocmin, scanenginelocmax ], val_time )

        # Yield the metrics
        yield metric1
        yield metric2
        yield metric3
        yield metric4
        yield metric5


if __name__ == '__main__':

    # Load and check configurations
    if (loadconfigurations() == False):
        sys.exit(70)

    try:

        # Use a new registry
        reg = CollectorRegistry()
        reg.register(CxCollector())
        start_http_server(_promport, registry=reg)

        # Run
        while True: 
            time.sleep(1)

    finally:
        # Log finish
        cleanup()

