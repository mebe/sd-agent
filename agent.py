#!/usr/bin/env python
'''
    Server Density
    www.serverdensity.com
    ----
    A web based server resource monitoring application

    Licensed under Simplified BSD License (see LICENSE)
    (C) Boxed Ice 2009 all rights reserved
'''

# General config
agentConfig = {}
agentConfig['debugMode'] = 1
agentConfig['checkFreq'] = 60

agentConfig['version'] = '0.0.1'

# Core modules
import ConfigParser
import logging
import os
import re
import sched
# import subprocess # Not available in IronPython
import sys
import time

# .Net WMI stuff
import clr
clr.AddReference("System.Management")
from System.Management import (
    ManagementClass,
    ManagementObject
)                   


# Check we're not using an old version of Python. We need 2.4 above because some modules (like subprocess)
# were only introduced in 2.4.
if int(sys.version_info[1]) <= 3:
    print 'You are using an outdated version of Python. Please update to v2.4 or above (v3 is not supported).'
    sys.exit(2)

# Custom modules
from checks import checks

# Config handling
try:
    path = os.path.realpath(__file__)
    path = os.path.dirname(path)

    config = ConfigParser.ConfigParser()
    if os.path.exists('/etc/sd-agent/config.cfg'):
        config.read('/etc/sd-agent/config.cfg')
    else:
        config.read(path + '/config.cfg')

    # Core config
    agentConfig['sdUrl'] = config.get('Main', 'sd_url')
    if agentConfig['sdUrl'].endswith('/'):
        agentConfig['sdUrl'] = agentConfig['sdUrl'][:-1]
    agentConfig['agentKey'] = config.get('Main', 'agent_key')
    agentConfig['tmpDirectory'] = '/tmp/' # default which may be overriden in the config later
    agentConfig['pidfileDirectory'] = agentConfig['tmpDirectory']

    # Optional config
    # Also do not need to be present in the config file (case 28326).    
    if config.has_option('Main', 'apache_status_url'):
        agentConfig['apacheStatusUrl'] = config.get('Main', 'apache_status_url')

    if config.has_option('Main', 'mysql_server'):
        agentConfig['MySQLServer'] = config.get('Main', 'mysql_server')

    if config.has_option('Main', 'mysql_user'):
        agentConfig['MySQLUser'] = config.get('Main', 'mysql_user')

    if config.has_option('Main', 'mysql_pass'):
        agentConfig['MySQLPass'] = config.get('Main', 'mysql_pass')

    if config.has_option('Main', 'nginx_status_url'):
        agentConfig['nginxStatusUrl'] = config.get('Main', 'nginx_status_url')

    if config.has_option('Main', 'tmp_directory'):
        agentConfig['tmpDirectory'] = config.get('Main', 'tmp_directory')

    # Stats reporting, optional (supports older agent versions without this config value)
    if config.has_option('Main', 'report_anon_stats'):
        agentConfig['reportAnonStats'] = config.get('Main', 'report_anon_stats')

    if config.has_option('Main', 'pidfile_directory'):
        agentConfig['pidfileDirectory'] = config.get('Main', 'pidfile_directory')

except ConfigParser.NoSectionError, e:
    print 'Config file not found or incorrectly formatted'
    sys.exit(2)

except ConfigParser.ParsingError, e:
    print 'Config file not found or incorrectly formatted'
    sys.exit(2)

except ConfigParser.NoOptionError, e:
    print 'There are some items missing from your config file, but nothing fatal'

# Check to make sure the default config values have been changed (only core config values)
if agentConfig['sdUrl'] == 'http://example.serverdensity.com' or agentConfig['agentKey'] == 'keyHere':
    print 'You have not modified config.cfg for your server'
    sys.exit(2)

# Check to make sure sd_url is in correct
if re.match('http(s)?(\:\/\/)[a-zA-Z0-9_\-]+\.(serverdensity.com)', agentConfig['sdUrl']) == None:
    print 'Your sd_url is incorrect. It needs to be in the form http://example.serverdensity.com (or using https)'
    sys.exit(2)

# Check apache_status_url is not empty (case 27073)
if agentConfig['apacheStatusUrl'] == None:
    print 'You must provide a config value for apache_status_url. If you do not wish to use Apache monitoring, leave it as its default value - http://www.example.com/server-status/?auto'
    sys.exit(2)

if 'nginxStatusUrl' in agentConfig and agentConfig['nginxStatusUrl'] == None:
    print 'You must provide a config value for nginx_status_url. If you do not wish to use Nginx monitoring, leave it as its default value - http://www.example.com/nginx_status'
    sys.exit(2)

if 'MySQLServer' in agentConfig and agentConfig['MySQLServer'] != '' and 'MySQLUser' in agentConfig and agentConfig['MySQLUser'] != '' and 'MySQLPass' in agentConfig and agentConfig['MySQLPass'] != '':
    try:
        import MySQLdb
    except ImportError:
        print 'You have configured MySQL for monitoring, but the MySQLdb module is not installed.  For more info, see: http://www.serverdensity.com/docs/agent/mysqlstatus/'
        sys.exit(2)

    # Override the generic daemon class to run our checks
class agent():
    def run(self):
        agentLogger = logging.getLogger('agent')

        agentLogger.debug('Collecting basic system stats')

        # Get some basic system stats to post back for development/testing
        import platform

        # platform.python_version() doesn't work in IronPython in 2.6: http://bugs.python.org/issue6388
        systemStats = {'machine': platform.machine(), 'platform': 'windows', 'processor': platform.processor(),
                       'pythonV': sys.version,
                       'cpuCores': int(sum(mo.GetPropertyValue('NumberOfCores') for mo in ManagementClass(
                               'Win32_Processor').GetInstances().GetEnumerator())) }

        systemStats['winV'] = ManagementClass('Win32_OperatingSystem').GetInstances().GetEnumerator().next(
                ).GetPropertyValue('Version')

        agentLogger.debug('System: ' + str(systemStats))

        # We use the system stats in the log but user might not want them posted back
        if 'reportAnonStats' in agentConfig and agentConfig['reportAnonStats'] == 'no':
            systemStats = None

        agentLogger.debug('Creating checks instance')

        # Checks instance
        c = checks(agentConfig)

        # Schedule the checks
        agentLogger.debug('Scheduling checks every ' + str(agentConfig['checkFreq']) + ' seconds')
        s = sched.scheduler(time.time, time.sleep)
        c.doChecks(s, True, systemStats) # start immediately (case 28315)
        s.run()

if __name__ == '__main__':
    # Obviously we can't deamonize in Windows, so let's do this the boring way
    # Logging
    if agentConfig['debugMode']:
        logFile = os.path.join(agentConfig['tmpDirectory'], 'sd-agent.log')
        logging.basicConfig(filename=logFile, filemode='w', level=logging.DEBUG,
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    mainLogger = logging.getLogger('main')
    mainLogger.debug('Agent called')
    mainLogger.debug('Agent version: ' + agentConfig['version'])

    agent = agent()
    while True:
        agent.run()