#!/usr/bin/python

#============================ adjust path =====================================

import sys
import os
if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, '..', '..','libs'))
    sys.path.insert(0, os.path.join(here, '..', '..','external_libs'))

#============================ verify installation =============================

from SmartMeshSDK.utils import SmsdkInstallVerifier
(goodToGo,reason) = SmsdkInstallVerifier.verifyComponents(
    [
        SmsdkInstallVerifier.PYTHON,
        SmsdkInstallVerifier.PYSERIAL,
    ]
)
if not goodToGo:
    print "Your installation does not allow this application to run:\n"
    print reason
    raw_input("Press any button to exit")
    sys.exit(1)

#============================ imports =========================================

import threading
import copy
import time
import traceback

from   SmartMeshSDK.utils              import AppUtils,                   \
                                              FormatUtils,                \
                                              LatencyCalculator
from   SmartMeshSDK.ApiDefinition      import IpMgrDefinition
from   SmartMeshSDK.IpMgrConnectorMux  import IpMgrSubscribe
from   SmartMeshSDK.ApiException       import APIError
from   SmartMeshSDK.protocols.oap      import OAPDispatcher,              \
                                              OAPClient,                  \
                                              OAPMessage,                 \
                                              OAPNotif
from   dustUI                          import dustWindow,                 \
                                              dustFrameApi,               \
                                              dustFrameConnection,        \
                                              dustFrameMoteList,          \
                                              dustFrameText

#============================ logging =========================================

# local

import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('App')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

# global

AppUtils.configureLogging()

#============================ helpers =========================================

def logcrash(err):
    output = traceback.format_exc()
    print output
    log.critical(output)

#============================ defines =========================================

GUI_UPDATEPERIOD = 250   # in ms

# columns names
COL_NOTIF_DATA   = IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA
COL_LAT_CUR      = 'lat. current'
COL_NOTIF_CLR    = 'clear counters'
COL_D0_GETSET    = 'DO enable'
COL_DIGITAL_0    = 'D0 (0/1)'
COL_DIGITAL_1    = 'D1 (0/1)'
COL_DIGITAL_2    = 'D2 (0/1)'
COL_DIGITAL_3    = 'D3 (0/1)'
COL_DIGITAL_NUM  = 'num. digital'
COL_DIGITAL_CLR  = 'clear digital' #copy clearTemp function
COL_DIGITAL_RATE = 'DI#/enable(0 or 1)/format(1=on change)'
DIGITAL_IN_ADDR  = 2
DI_0             = 0
DI_1             = 1
DI_2             = 2  
DI_3             = 3

#============================ body ============================================

##
# \addtogroup DigitalMonitor
# \{
# 

class notifClient(object):
    
    def __init__(self, apiDef, connector, disconnectedCallback, latencyCalculator):
        
        # store params
        self.apiDef               = apiDef
        self.connector            = connector
        self.disconnectedCallback = disconnectedCallback
        self.latencyCalculator    = latencyCalculator
        
        # log
        log.debug("Initialize notifClient")
        
        # variables
        self.dataLock             = threading.Lock()
        self.isMoteActive         = {}
        self.data                 = {}
        self.updates              = {}
        
        # subscriber
        if   isinstance(self.apiDef,IpMgrDefinition.IpMgrDefinition):
            # we are connected to an IP manager
            
            self.subscriber = IpMgrSubscribe.IpMgrSubscribe(self.connector)
            self.subscriber.start()
            self.subscriber.subscribe(
                notifTypes =    [
                                    IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA,
                                ],
                fun =           self._dataCallback,
                isRlbl =        False,
            )
            self.subscriber.subscribe(
                notifTypes =    [
                                    IpMgrSubscribe.IpMgrSubscribe.NOTIFEVENT,
                                ],
                fun =           self._eventCallback,
                isRlbl =        True,
            )
            self.subscriber.subscribe(
                notifTypes =    [
                                    IpMgrSubscribe.IpMgrSubscribe.ERROR,
                                    IpMgrSubscribe.IpMgrSubscribe.FINISH,
                                ],
                fun =           self.disconnectedCallback,
                isRlbl =        True,
            )
        
        else:
            output = "apiDef of type {0} unexpected".format(type(self.apiDef))
            log.critical(output)
            print output
            raise SystemError(output)
        
        # OAP dispatcher
        self.oap_dispatch = OAPDispatcher.OAPDispatcher()
        self.oap_dispatch.register_notif_handler(self._handle_oap_notif)
    
    #======================== public ==========================================
    
    def getData(self):
        self.dataLock.acquire()
        returnIsMoteActive   = copy.deepcopy(self.isMoteActive)
        returnData           = copy.deepcopy(self.data)
        returnUpdates        = copy.deepcopy(self.updates)
        self.updates         = {}
        self.dataLock.release()
        return (returnIsMoteActive,returnData,returnUpdates)
    
    def getOapDispatcher(self):
        return self.oap_dispatch
    
    def clearNotifCounters(self,mac):
        self.dataLock.acquire()
        self.updates = {}
        if mac in self.data:
            self.updates[mac] = []
            for k,v in self.data[mac].items():
                if   k in [COL_NOTIF_DATA,]:
                    self.updates[mac].append(k)
                    self.data[mac][k] = 0
                elif k in [COL_LAT_CUR,]:
                    self.updates[mac].append(k)
                    self.data[mac][k] = '-'
        self.dataLock.release()
        
    def clearDigital(self,mac):
        self.dataLock.acquire()
        self.updates = {}
        if mac in self.data:
            self.updates[mac] = []
            for k,v in self.data[mac].items():
                if   k in [COL_DIGITAL_NUM,]:
                    self.updates[mac].append(k)
                    self.data[mac][k] = 0
                if   k in [COL_DIGITAL_1,]:
                    self.updates[mac].append(k)
                    self.data[mac][k] = '-'
        self.dataLock.release()
        
    def disconnect(self):
        self.connector.disconnect()
    
    #======================== private =========================================
    
    def _dataCallback(self, notifName, notifParams):
        
        try:
            # log
            if   isinstance(self.apiDef,IpMgrDefinition.IpMgrDefinition):
                # IpMgrSubscribe generates a named tuple
                log.debug(
                    "notifClient._dataCallback {0}:\n{1}".format(
                        notifName,
                        FormatUtils.formatNamedTuple(notifParams)
                    )
                )
            else:
                output = "apiDef of type {0} unexpected".format(type(self.apiDef))
                log.critical(output)
                print output
                raise SystemError(output)
            
            # record current time
            timeNow = time.time()
            
            # read MAC address from notification
            mac = self._getMacFromNotifParams(notifParams)
            
            # lock the data structure
            self.dataLock.acquire()
            
            # add mac/type to data, if necessary
            if mac not in self.data:
                self.data[mac] = {}
            if notifName not in self.data[mac]:
                self.data[mac][notifName] = 0
                
            # add mac/type to updates, if necessary
            if mac not in self.updates:
                self.updates[mac] = []
            if notifName not in self.updates[mac]:
                self.updates[mac].append(notifName)
            
            # increment counter
            self.data[mac][notifName] += 1
            
            # calculate latency
            try:
                if notifName in [IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA,
                                 IpMgrSubscribe.IpMgrSubscribe.NOTIFIPDATA,]:
                    try:
                        latency = self.latencyCalculator.getLatency(
                                float(notifParams.utcSecs)+(float(notifParams.utcUsecs)/1000000.0),
                                timeNow)
                        # lat. current
                        if COL_LAT_CUR not in self.data[mac]:
                            self.data[mac][COL_LAT_CUR] = '-'
                        if COL_LAT_CUR not in self.updates[mac]:
                            self.updates[mac].append(COL_LAT_CUR)
                        self.data[mac][COL_LAT_CUR] = latency
                    except RuntimeError:
                        # can happen if latency calculator hasn't acquired lock yet
                        pass
            except Exception as err:
                print err
            
            # unlock the data structure
            self.dataLock.release()
            
            # parse OAP packet
            if notifName in [IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA]:
                self.oap_dispatch.dispatch_pkt(notifName, notifParams)
        except Exception as err:
            logcrash(err)
    
    def _eventCallback(self, notifName, notifParams):
        
        try:
        
            # log
            log.debug("notifClient._eventCallback {0} {1}".format(notifName, notifParams))
            
            # lock the data structure
            self.dataLock.acquire()
            
            if   isinstance(self.apiDef,IpMgrDefinition.IpMgrDefinition):
                
                if notifName in [IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEOPERATIONAL]:
                    mac = self._getMacFromNotifParams(notifParams)
                    self.isMoteActive[mac] = True
                    
                if notifName in [IpMgrSubscribe.IpMgrSubscribe.EVENTMOTELOST]:
                    mac = self._getMacFromNotifParams(notifParams)
                    self.isMoteActive[mac] = False
                
            else:
                output = "apiDef of type {0} unexpected".format(type(self.apiDef))
                log.critical(output)
                print output
                raise SystemError(output)
        
        except Exception as err:
            logcrash(err)
        
        finally:
            
            # unlock the data structure
            self.dataLock.release()
    
    def _getMacFromNotifParams(self,notifParams):
        
        if   isinstance(self.apiDef,IpMgrDefinition.IpMgrDefinition):
            # we are connected to an IP manager
            
            return tuple(notifParams.macAddress)

        else:
            output = "apiDef of type {0} unexpected".format(type(self.apiDef))
            log.critical(output)
            print output
            raise SystemError(output)
    
    def _handle_oap_notif(self,mac,notif):
        
        # convert MAC to tuple
        mac = tuple(mac)
            
        #if isinstance(notif,OAPNotif.OAPSample):
        if isinstance(notif,OAPNotif.OAPDigitalIn):
            # this is a digital in notification
            if notif.channel[0] == DIGITAL_IN_ADDR:
                # this is a digital notification
            
                # lock the data structure
                self.dataLock.acquire()
            
                # add mac/type to data, if necessary
                if mac not in self.data:
                    self.data[mac] = {}
                if COL_DIGITAL_0 not in self.data[mac]:
                    self.data[mac][COL_DIGITAL_0] = None
                if COL_DIGITAL_1 not in self.data[mac]:
                    self.data[mac][COL_DIGITAL_1] = None
                if COL_DIGITAL_2 not in self.data[mac]:
                    self.data[mac][COL_DIGITAL_2] = None                    
                if COL_DIGITAL_3 not in self.data[mac]:
                    self.data[mac][COL_DIGITAL_3] = None
                if COL_DIGITAL_NUM not in self.data[mac]:
                    self.data[mac][COL_DIGITAL_NUM]   = 0
            
                # add mac/type to updates, if necessary
                if mac not in self.updates:
                    self.updates[mac] = []
                if COL_DIGITAL_0 not in self.updates[mac]:
                    self.updates[mac].append(COL_DIGITAL_0)               
                if COL_DIGITAL_1 not in self.updates[mac]:
                    self.updates[mac].append(COL_DIGITAL_1)                  
                if COL_DIGITAL_2 not in self.updates[mac]:
                    self.updates[mac].append(COL_DIGITAL_2)                     
                if COL_DIGITAL_3 not in self.updates[mac]:  
                    self.updates[mac].append(COL_DIGITAL_3)
                if COL_DIGITAL_NUM not in self.updates[mac]:
                    self.updates[mac].append(COL_DIGITAL_NUM)

                if notif.channel[1] == DI_0:
                    self.data[mac][COL_DIGITAL_0]  = notif.new_val
                elif notif.channel[1] == DI_1:
                    self.data[mac][COL_DIGITAL_1]  = notif.new_val
                elif notif.channel[1] == DI_2:
                    self.data[mac][COL_DIGITAL_2]  = notif.new_val
                elif notif.channel[1] == DI_3:
                    self.data[mac][COL_DIGITAL_3]  = notif.new_val
                self.data[mac][COL_DIGITAL_NUM]   += 1
            
                # unlock the data structure
                self.dataLock.release()

class DigitalMonitorGui(object):
    
    def __init__(self):
        
        # local variables
        self.guiLock            = threading.Lock()
        self.apiDef             = IpMgrDefinition.IpMgrDefinition()
        self.notifClientHandler = None
        self.latencyCalculator  = None
        self.guiUpdaters        = 0
        self.oap_clients        = {}
        
        # create window
        self.window = dustWindow.dustWindow('DigitalMonitor',
                                 self._windowCb_close)
        
        # add a API selection frame
        self.apiFrame = dustFrameApi.dustFrameApi(
                                    self.window,
                                    self.guiLock,
                                    self._apiFrameCb_apiLoaded,
                                    row=0,column=0,
                                    deviceType=dustFrameApi.dustFrameApi.MANAGER)
        self.apiFrame.show()
        
        # add a connection frame
        self.connectionFrame = dustFrameConnection.dustFrameConnection(
                                    self.window,
                                    self.guiLock,
                                    self._connectionFrameCb_connected,
                                    frameName="manager connection",
                                    row=1,column=0)
        
        # add a mote list frame
        columnnames =       [
                                # counters and latency
                                {
                                    'name': COL_NOTIF_DATA,
                                    'type': dustFrameMoteList.dustFrameMoteList.LABEL,
                                },
                                {
                                    'name': COL_LAT_CUR,
                                    'type': dustFrameMoteList.dustFrameMoteList.LABEL,
                                },
                                {
                                    'name': COL_NOTIF_CLR,
                                    'type': dustFrameMoteList.dustFrameMoteList.ACTION,
                                },
                                #digital configuration
                                {
                                    'name': COL_DIGITAL_NUM,
                                    'type': dustFrameMoteList.dustFrameMoteList.LABEL,
                                },     
                                {
                                    'name': COL_DIGITAL_CLR,
                                    'type': dustFrameMoteList.dustFrameMoteList.ACTION,
                                },   
                                {
                                    'name': COL_DIGITAL_RATE,
                                    'type': dustFrameMoteList.dustFrameMoteList.SETTHREEVAL,
                                },   
                                #digital values
                                {
                                    'name': COL_D0_GETSET,
                                    'type': dustFrameMoteList.dustFrameMoteList.GETSETONEVAL,
                                },                                 
                                {
                                    'name': COL_DIGITAL_0,
                                    'type': dustFrameMoteList.dustFrameMoteList.LABEL,
                                },  
                                {
                                    'name': COL_DIGITAL_1,
                                    'type': dustFrameMoteList.dustFrameMoteList.LABEL,
                                },  
                                {
                                    'name': COL_DIGITAL_2,
                                    'type': dustFrameMoteList.dustFrameMoteList.LABEL,
                                },  
                                {
                                    'name': COL_DIGITAL_3,
                                    'type': dustFrameMoteList.dustFrameMoteList.LABEL,
                                },                                  
                            ]
        self.moteListFrame = dustFrameMoteList.dustFrameMoteList(self.window,
                                               self.guiLock,
                                               columnnames,
                                               row=2,column=0)
        self.moteListFrame.show()
        
        # add a status (text) frame
        self.statusFrame   = dustFrameText.dustFrameText(
                                    self.window,
                                    self.guiLock,
                                    frameName="status",
                                    row=3,column=0)
        self.statusFrame.show()
    
    #======================== public ==========================================
    
    def start(self):
        
        # log
        log.debug("Starting DigitalMonitorGui")
        
        # start Tkinter's main thead
        try:
            self.window.mainloop()
        except SystemExit:
            sys.exit()

    #======================== private =========================================
    
    #===== user interaction
    
    def _apiFrameCb_apiLoaded(self,apiDefLoaded):
        '''
        \brief Called when an API is selected.
        '''
        
        # log
        log.debug("_apiFrameCb_apiLoaded")
        
        # record the loaded API
        self.apiDef = apiDefLoaded
        
        # tell other frames about it
        self.connectionFrame.apiLoaded(self.apiDef)
        
        # display frames
        self.connectionFrame.show()
        
        # update status
        self.statusFrame.write("API {0} loaded successfully.".format(type(apiDefLoaded)))
    
    def _connectionFrameCb_connected(self,connector):
        '''
        \brief Called when the connectionFrame has connected.
        '''
        
        # log
        log.debug("_connectionFrameCb_connected")
        
        # store the connector
        self.connector = connector
        
        # start a latency calculator
        self.latencyCalculator = LatencyCalculator.LatencyCalculator(self.apiDef,self.connector)
        self.latencyCalculator.start()
        
        # start a notification client
        self.notifClientHandler = notifClient(
            self.apiDef,
            self.connector,
            self._connectionFrameCb_disconnected,
            self.latencyCalculator,
        )
        
        # retrieve list of motes from manager
        macs = self._getOperationalMotesMacAddresses()
        for mac in macs:
            self._addNewMote(mac)
        
        # clear the colors on the GUI
        self.moteListFrame.clearColors()
        
        # schedule the GUI to update itself in GUI_UPDATEPERIOD ms
        if self.guiUpdaters==0:
            self.moteListFrame.after(GUI_UPDATEPERIOD,self._updateMoteList)
            self.guiUpdaters += 1
        
        # update status
        self.statusFrame.write("Connection to manager successful.")
    
    def _moteListFrameCb_clearCtrs(self,mac,button):
        # clear the counters
        self.notifClientHandler.clearNotifCounters(mac)
        
        # update status
        self.statusFrame.write(
                "Counters for mote {0} cleared successfully.".format(
                    FormatUtils.formatMacString(mac),
                )
            )
              
    def _moteListFrameCb_clearDigital(self,mac,button):
        # clear the digital data
        self.notifClientHandler.clearDigital(mac)
        
        # update status
        self.statusFrame.write(
                "Digital data for mote {0} cleared successfully.".format(
                    FormatUtils.formatMacString(mac),
                )
            )

    def _moteListFrameCb_D0rateGet(self,mac):
        
        # send the OAP message
        try:
            self.oap_clients[mac].send( OAPMessage.CmdType.GET,                    # command
                                        [2,0],                                     # address
                                        data_tags=None,                            # parameters
                                        cb=self._oap_rateGet_resp,                 # callback
                                      )
        except APIError as err:
            self.statusFrame.write("[WARNING] {0}".format(err))
        else:
            # update status
            self.statusFrame.write(
                "Get request sent successfully to mote {0}.".format(
                    FormatUtils.formatMacString(mac),
                )
            )
    
    def _moteListFrameCb_D0rateSet(self,mac,val):
    
        # send the OAP message
        try:
            self.oap_clients[mac].send(
                OAPMessage.CmdType.PUT,                    # command
                [2,0],                                     # address
                data_tags=[OAPMessage.TLVByte(t=0,v=val),
                           OAPMessage.TLVByte(t=1,v=1),],  # parameters
                cb=None,                                   # callback
              )
        except APIError as err:
            self.statusFrame.write("[WARNING] {0}".format(err))
        else:
            # update status
            self.statusFrame.write(
                "Enable ({0}) request sent successfully to mote {1}.".format(
                    val,
                    FormatUtils.formatMacString(mac),
                )
            )
            
    def _moteListFrameCb_digRateSet(self,mac,(val1,val2,val3)):
    
        # send the OAP message
        try:
            self.oap_clients[mac].send(
                OAPMessage.CmdType.PUT,                         # command
                    [DIGITAL_IN_ADDR,val1],                     # address
                    data_tags=[OAPMessage.TLVByte(t=0,v=val2),
                               OAPMessage.TLVByte(t=3,v=val3),],# parameters
                    cb=None,                                    # callback
                )
        except APIError as err:
            self.statusFrame.write("[WARNING] {0}".format(err))
        else:
            # update status
            self.statusFrame.write(
                "Configuration request sent successfully to mote {0} on digital input {1}.".format(
                    FormatUtils.formatMacString(mac),
                    val1
                )
            )
    
    def _connectionFrameCb_disconnected(self,notifName=None,notifParams=None):
        '''
        \brief Called when the connectionFrame has disconnected.
        '''
        
        # kill the latency calculator thread
        if self.latencyCalculator:
            self.latencyCalculator.disconnect()
            self.latencyCalculator = None
        
        # update the GUI
        self.connectionFrame.updateGuiDisconnected()
        
        # delete the connector
        self.connector = None
    
    def _windowCb_close(self):
        if self.latencyCalculator:
            self.latencyCalculator.disconnect()
        if self.notifClientHandler:
            self.notifClientHandler.disconnect()
    
    #===== helpers
    
    def _getOperationalMotesMacAddresses(self):
        returnVal = []
        
        if   isinstance(self.apiDef,IpMgrDefinition.IpMgrDefinition):
            # we are connected to an IP manager
            
            currentMac     = (0,0,0,0,0,0,0,0) # start getMoteConfig() iteration with the 0 MAC address
            continueAsking = True
            while continueAsking:
                try:
                    res = self.connector.dn_getMoteConfig(currentMac,True)
                except APIError:
                    continueAsking = False
                else:
                    if ((not res.isAP) and (res.state in [4,])):
                        returnVal.append(tuple(res.macAddress))
                    currentMac = res.macAddress
        
        
        else:
            output = "apiDef of type {0} unexpected".format(type(self.apiDef))
            log.critical(output)
            print output
            raise SystemError(output)
        
        # order by increasing MAC address
        returnVal.sort()
        
        return returnVal
    
    def _addNewMote(self,mac):
    
        # add mote to GUI
        # Note: if you're reconnecting, mote already exists
        
        columnvals = {
            # counters and latency
            COL_NOTIF_DATA:            0,
            COL_LAT_CUR:             '-',
            COL_NOTIF_CLR:          {
                                        'text':     'clear',
                                        'callback': self._moteListFrameCb_clearCtrs,
                                    },
            # digital
            COL_D0_GETSET:          {
                                        'min':      0,
                                        'max':      1,
                                        'cb_get':   self._moteListFrameCb_D0rateGet,
                                        'cb_set':   self._moteListFrameCb_D0rateSet,
                                    },
            COL_DIGITAL_0:          '-',
            COL_DIGITAL_1:          '-',
            COL_DIGITAL_2:          '-',
            COL_DIGITAL_3:          '-',
            COL_DIGITAL_NUM:           0,
            COL_DIGITAL_CLR:        {
                                        'text':     'clear',
                                        'callback': self._moteListFrameCb_clearDigital,
                                    },
            COL_DIGITAL_RATE:       {
                                        'min2':     0,
                                        'max2':     1,
                                        'min3':     0,
                                        'max3':     3,                                        
                                        'cb_set':   self._moteListFrameCb_digRateSet,
                                    },                                     
        }
        
        if mac not in self.oap_clients:
            self.moteListFrame.addMote(
                    mac,
                    columnvals,
                )
        
        # create OAPClient
        # Note: if you're reconnecting, this recreates the OAP client
        self.oap_clients[mac] = OAPClient.OAPClient(mac,
                                                    self._sendDataToConnector,
                                                    self.notifClientHandler.getOapDispatcher())
    
    def _oap_rateGet_resp(self,mac,oap_resp):
        
        temp = OAPMessage.Sensor()
        temp.parse_response(oap_resp)
        
        log.debug("I just tried to parse an OAP Response")

        if temp.addr == [2,0]:
            self.statusFrame.write("I got back what I expected, bro: {0}".format(temp.addr))
        else:
            self.statusFrame.write("This is what I got back, bro: {0}".format(temp.addr))
        
        
        #self.moteListFrame.update(mac, COL_D0_GETSET, temp.enable.value)   


    def _updateMoteList(self):
        
        updatable_columns = [
                                COL_NOTIF_DATA,
                                COL_LAT_CUR,
                                COL_D0_GETSET,
                                COL_DIGITAL_0,
                                COL_DIGITAL_1,
                                COL_DIGITAL_2,
                                COL_DIGITAL_3,
                                COL_DIGITAL_NUM,
                            ]
        
        # get the data
        (isMoteActive,data,updates) = self.notifClientHandler.getData()
        
        # update the frame
        for mac,data in data.items():
            
            # detect new motes
            if mac not in self.oap_clients:
                self._addNewMote(mac)
            
            # update
            for columnname,columnval in data.items():
                if columnname in updatable_columns:
                    if ((mac in updates) and (columnname in updates[mac])):
                        self.moteListFrame.update(mac,columnname,columnval)
        
        # enable/disable motes
        for mac in isMoteActive:
            if isMoteActive[mac]:
                self.moteListFrame.enableMote(mac)
            else:
                self.moteListFrame.disableMote(mac)
        
        # schedule the next update
        self.moteListFrame.after(GUI_UPDATEPERIOD,self._updateMoteList)
    
    def _sendDataToConnector(self,mac,priority,srcPort,dstPort,options,data):
        
        if   isinstance(self.apiDef,IpMgrDefinition.IpMgrDefinition):
            # we are connected to an IP manager
            
            self.connector.dn_sendData(
                mac,
                priority,
                srcPort,
                dstPort,
                options,
                data
            )
        else:
            output = "apiDef of type {0} unexpected".format(type(self.apiDef))
            log.critical(output)
            print output
            raise SystemError(output)

#============================ main ============================================

def main():
    DigitalMonitorGuiHandler = DigitalMonitorGui()
    DigitalMonitorGuiHandler.start()

if __name__ == '__main__':
    main()

##
# end of DigitalMonitor
# \}
# 
