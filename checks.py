'''
    Server Density
    www.serverdensity.com
    ----
    A web based server resource monitoring application

    Licensed under Simplified BSD License (see LICENSE)
    (C) Boxed Ice 2009 all rights reserved
'''

# SO references
# http://stackoverflow.com/questions/446209/possible-values-from-sys-platform/446210#446210
# http://stackoverflow.com/questions/682446/splitting-out-the-output-of-ps-using-python/682464#682464
# http://stackoverflow.com/questions/1052589/how-can-i-parse-the-output-of-proc-net-dev-into-keyvalue-pairs-per-interface-us

# Core modules
import httplib # Used only for handling httplib.HTTPException (case #26701)
import logging
import logging.handlers
import platform
import re
# import subprocess # Not available in IronPython
import sys
import urllib
import urllib2
import math
import datetime

# .Net WMI stuff
from System import Array
import clr
clr.AddReference("System.Management")
from System.Management import (
    ManagementClass,
    ManagementObject,
    ManagementObjectSearcher
)


# Avoids depreciation warning on newer Python versions (case 29048)
try:
    from hashlib import md5
except:
    import md5

# platform for reading version info isn't supported on IronPython in 2.6: http://bugs.python.org/issue6388

# We need to return the data using JSON. As of Python 2.6+, there is a core JSON
# module. We have a 2.4/2.5 compatible lib included with the agent but if we're
# on 2.6 or above, we should use the core module which will be faster
pythonVersion = sys.version_info

# Build the request headers
headers = {
'User-Agent': 'Server Density Windows Agent',
'Content-Type': 'application/x-www-form-urlencoded',
'Accept': 'text/html, */*',
}

if int(pythonVersion[1]) >= 6: # Don't bother checking major version since we only support v2 anyway
    import json
else:
    import minjson

class checks:
    def __init__(self, agentConfig):
        self.agentConfig = agentConfig
        self.networkTrafficStore = {}
        self.topIndex = 0
        self.os = "windows"

    def getDiskUsage(self):
        self.checksLogger.debug('getDiskUsage: start')

        def buildUsageData(usageData):
            usageData['usedSpace'] = usageData['totalSpace'] - usageData['freeSpace']
            if usageData['totalSpace'] == 0: usageData['percentUsed'] = 0
            else: usageData['percentUsed'] = int(
                    math.ceil(usageData['usedSpace'] / usageData['totalSpace']) * 100)
            return usageData

        usageData = [[usageData['id'],
                      long(usageData['totalSpace']),
                      int(usageData['usedSpace'] / 1024.0 / 1024.0),
                      int(usageData['freeSpace'] / 1024.0 / 1024.0),
                      str(usageData['percentUsed']) + '%',
                      usageData['mountPoint']]
                     for usageData in map(buildUsageData, [dict(
                id = mo.GetPropertyValue('VolumeSerialNumber'),
                mountPoint = mo.GetPropertyValue('DeviceID'),
                totalSpace = round((mo.GetPropertyValue('Size') or 0) / 1024.0),
                freeSpace = round((mo.GetPropertyValue('FreeSpace') or 0) / 1024.0)
                ) for mo in ManagementClass('Win32_LogicalDisk').GetInstances()])]

        self.checksLogger.debug('getDiskUsage: completed, returning')

        return usageData

    def getLoadPercentage(self):
    # Windows doesn't really do load averages, so we'll just return a sum of cpu load percentages.
    # Not really a good idea, but I can't think of anything better atm.

        self.checksLogger.debug('getLoadPercentage: start')

        loadPercentage = sum(mo.GetPropertyValue('LoadPercentage') or 0 for mo in ManagementClass(
                'Win32_Processor').GetInstances())

        self.checksLogger.debug('getLoadPercentage: completed, returning')

        return loadPercentage

    def getMemoryUsage(self):
        self.checksLogger.debug('getMemoryUsage: start')

        # These are all over the place. Hopefully I found the right ones
        csMo  = ManagementObjectSearcher('SELECT TotalPhysicalMemory FROM Win32_ComputerSystem').Get(
                ).GetEnumerator().next() # This is in bytes
        osMo  = ManagementObjectSearcher(
                'SELECT FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles FROM Win32_OperatingSystem'
                ).Get().GetEnumerator().next() # These are in kilobytes
        # memMo = ManagementObjectSearcher('SELECT CacheBytes FROM Win32_PerfFormattedData_PerfOS_Memory').Get().GetEnumerator().next() # This is in bytes

        memData =  {
        'physTotal': csMo.GetPropertyValue('TotalPhysicalMemory') / 1024.0 / 1024.0,
        'physFree':  osMo.GetPropertyValue('FreePhysicalMemory') / 1024.0,
        'swapTotal': osMo.GetPropertyValue('SizeStoredInPagingFiles') / 1024.0,
        'swapFree':  osMo.GetPropertyValue('FreeSpaceInPagingFiles') / 1024.0,
        #    'cached':    memMo.GetPropertyValue('CacheByes') / 1024.0 / 1024.0 # Raises "SystemError: Not found" for some reason
        }

        memData['swapUsed'] = memData['swapTotal'] - memData['swapFree']
        memData['physUsed'] = memData['physTotal'] - memData['physFree']

        memData = dict((k, round(v, 1)) for k, v in memData.iteritems())

        memData['cached'] = None

        self.checksLogger.debug('getMemoryUsage: completed, returning')

        return memData

    def getNetworkTraffic(self):
        self.checksLogger.debug('getNetworkTraffic: start')

        def trafficDiff(iface):
            if iface['name'] not in self.networkTrafficStore:
                diffs = {}
            else:
                oldData = self.networkTrafficStore[iface['name']]
                diffs = {'recv_bytes': iface['recv_bytes'] - oldData['recv_bytes'],
                         'trans_bytes': iface['trans_bytes'] - oldData['trans_bytes'] }

            self.networkTrafficStore[iface['name']] = {'recv_bytes': iface['recv_bytes'],
                                                       'trans_bytes': iface['trans_bytes']}
            return diffs

        # BytesReceivedPerSec/BytesSentPerSec actually contain the byte counters in the RAW performance data object.
        # Win32_PerfFormatted Data_Tcpip_NetworkInterface on the other hand contains the actual per second values.
        interfaces = [trafficDiff(iface) for iface in [dict(
                name = mo.GetPropertyValue('Name'),
                recv_bytes = long(mo.GetPropertyValue('BytesReceivedPerSec')),
                trans_bytes = long(mo.GetPropertyValue('BytesSentPerSec'))) for mo in ManagementClass(
                'Win32_PerfRawData_Tcpip_NetworkInterface').GetInstances()]]

        self.checksLogger.debug('getNetworkTraffic: completed, returning')

        return interfaces

    def getProcesses(self):
        self.checksLogger.debug('getProcesses: start')

        def getCpuUsage(mo):
            return ManagementObjectSearcher(
                    'SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfProc_Process WHERE IDProcess = "%s"' %
                    mo.GetPropertyValue('ProcessID')).Get().GetEnumerator().next().GetPropertyValue(
                    'PercentProcessorTime')

        def getOwner(mo):
            result = Array.CreateInstance(object, 2)
            mo.InvokeMethod('GetOwner', result)
            return result[0]

        processes = [[p['owner'],
                      p['id'],
                      p['cpuUsage'],
                      None, # Memory percentage doesn't seem to be available and I'm too lazy to calculate it myself
                      p['virtualSize'],
                      p['virtualSize'] - p['pfUsage'], # Resident size
                      '??', # No TTYs in Windows
                      None, # No process state in Windows
                      p['creationDate'],
                      p['cpuTime']
                ] for p in [dict(
                id = int(mo.GetPropertyValue('ProcessID')),
                virtualSize = long(mo.GetPropertyValue('VirtualSize') / 1024),
                pfUsage = long(mo.GetPropertyValue('PageFileUsage')),
                exePath = mo.GetPropertyValue('ExecutablePath'),
                creationDate = mo.GetPropertyValue('CreationDate'),
                cpuTime = str(datetime.timedelta(microseconds=(
                mo.GetPropertyValue('KernelModeTime') + mo.GetPropertyValue('UserModeTime')) / 10)),
                cpuUsage = int(getCpuUsage(mo)),
                owner = getOwner(mo)
                ) for mo in ManagementClass('Win32_Process').GetInstances()]]

        self.checksLogger.debug('getProcesses: completed, returning')

        return processes

    def doPostBack(self, postBackData):
        self.checksLogger.debug('doPostBack: start')

        try:
            self.checksLogger.debug('doPostBack: attempting postback: ' + self.agentConfig['sdUrl'])

            # Build the request handler
            request = urllib2.Request(self.agentConfig['sdUrl'] + '/postback/', postBackData, headers)

            # Do the request, log any errors
            response = urllib2.urlopen(request)

            self.checksLogger.debug('doPostBack: postback response: ' + str(response.read()))

        except urllib2.HTTPError, e:
            self.checksLogger.error('doPostBack: HTTPError = ' + str(e))
            return False

        except urllib2.URLError, e:
            self.checksLogger.error('doPostBack: URLError = ' + str(e))
            return False

        except httplib.HTTPException, e: # Added for case #26701
            self.checksLogger.error('doPostBack: HTTPException')
            return False

        except Exception, e:
            import traceback
            self.checksLogger.error('doPostBack: Exception = ' + traceback.format_exc())
            return False

        self.checksLogger.debug('doPostBack: completed')

    def doChecks(self, sc, firstRun, systemStats=False):
        macV = None
        if sys.platform == 'darwin':
            macV = platform.mac_ver()

        if not self.topIndex: # We cache the line index from which to read from top
        # Output from top is slightly modified on OS X 10.6 (case #28239)
            if macV and macV[0].startswith('10.6.'):
                self.topIndex = 6
            else:
                self.topIndex = 5

        if not self.os:
            if macV:
                self.os = 'mac'
            else:
                self.os = 'linux'

        self.checksLogger = logging.getLogger('checks')

        self.checksLogger.debug('doChecks: start')

        # Do the checks
        diskUsage = self.getDiskUsage()
        loadPercentage = self.getLoadPercentage()
        memory = self.getMemoryUsage()
        networkTraffic = self.getNetworkTraffic()
        processes = self.getProcesses()

        self.checksLogger.debug('doChecks: checks success, build payload')

        checksData = {'os' : self.os, 'agentKey' : self.agentConfig['agentKey'],
                      'agentVersion' : self.agentConfig['version'], 'diskUsage' : diskUsage, 'loadAvrg' : loadPercentage
                      , 'memPhysUsed' : memory['physUsed'], 'memPhysFree' : memory['physFree'],
                      'memSwapUsed' : memory['swapUsed'], 'memSwapFree' : memory['swapFree'],
                      'memCached' : memory['cached'], 'networkTraffic' : networkTraffic, 'processes' : processes}

        self.checksLogger.debug('doChecks: payload built, build optional payloads')

        # Include system stats on first postback
        if firstRun == True:
            checksData['systemStats'] = systemStats
            self.checksLogger.debug('doChecks: built optional payload systemStats')

        # Include server indentifiers
        import socket

        try:
            checksData['internalHostname'] = socket.gethostname()

        except socket.error, e:
            self.checksLogger.debug('Unable to get hostname: ' + str(e))

        self.checksLogger.debug('doChecks: payloads built, convert to json')

        # Post back the data
        if int(pythonVersion[1]) >= 6:
            self.checksLogger.debug('doChecks: json convert')

            payload = json.dumps(checksData)

            self.checksLogger.debug('Payload:' + payload)

        else:
            self.checksLogger.debug('doChecks: minjson convert')

            payload = minjson.write(checksData)

        self.checksLogger.debug('doChecks: json converted, hash')

        payloadHash = md5(payload).hexdigest() # Don't call new()
        postBackData = urllib.urlencode({'payload' : payload, 'hash' : payloadHash})

        self.checksLogger.debug('doChecks: hashed, doPostBack')

        self.doPostBack(postBackData)

        self.checksLogger.debug('doChecks: posted back, reschedule')

        sc.enter(self.agentConfig['checkFreq'], 1, self.doChecks, (sc, False))