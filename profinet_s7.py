#coding:utf-8
#!usr/bin/python3

# Référence : SiemensScan.py (Photubias)
#             profinet_scanner.py (tij1)

# Basé sur la DLL https://code.google.com/p/winpcapy/

# Date : 21/03/2023 (FR).




# IMPORTATION DES BIBLIOTHEQUES ###############################################################################################################################
import os
import sys
import re
import time
import string
import struct
import socket
import select
from subprocess import Popen, PIPE
from multiprocessing.pool import ThreadPool
from binascii import hexlify, unhexlify
from ctypes import CDLL, POINTER, Structure, c_void_p, c_char_p, c_ushort, c_char, c_long, c_int, c_uint, c_ubyte, byref, create_string_buffer
from ctypes.util import find_library

# CREATION DES CLASSES ########################################################################################################################################
class couleur:
   violet = '\033[95m'
   cyan = '\033[96m'
   cyanfonce = '\033[36m'
   bleu = '\033[94m'
   vert = '\033[92m'
   jaune= '\033[93m'
   rouge = '\033[91m'
   blanc = '\033[97m'
   gras = '\033[1m'
   souligne = '\033[4m'
   fin= '\033[0m'

class sockaddr(Structure):
    _fields_ = [("sa_family", c_ushort),
                ("sa_data", c_char * 14)]

class pcap_addr(Structure):
    pass
pcap_addr._fields_ = [('next', POINTER(pcap_addr)),
                      ('addr', POINTER(sockaddr)),
                      ('netmask', POINTER(sockaddr)),
                      ('broadaddr', POINTER(sockaddr)),
                      ('dstaddr', POINTER(sockaddr))]

class pcap_if(Structure):
    pass
pcap_if._fields_ = [('next', POINTER(pcap_if)),
                    ('name', c_char_p),
                    ('description', c_char_p),
                    ('addresses', POINTER(pcap_addr)),
                    ('flags', c_int)]

class timeval(Structure):
    pass
timeval._fields_ = [('tv_sec', c_long),
                    ('tv_usec', c_long)]

class pcap_pkthdr(Structure):
    _fields_ = [('ts', timeval),
                ('caplen', c_int),
                ('len', c_int)]

# INITIALISATION DE PCAP ######################################################################################################################################
if os.name == 'nt':
    try:
        os.chdir('C:/Windows/System32/Npcap')
        _lib = CDLL('wpcap.dll')
    except:
        print("Erreur : WinPcap/Npcap non installé.")
        input("Appuyer sur Entrée pour fermer")
        sys.exit(1)
else:
    pcaplibrary = find_library('pcap')
    if pcaplibrary == None or str(pcaplibrary) == '':
        print("Erreur : Librairie Pcap non installée.")
        input("Appuyer sur Entrée pour fermer")
        sys.exit(1)
    _lib = CDLL(pcaplibrary)

pcap_findalldevs = _lib.pcap_findalldevs
pcap_findalldevs.restype = c_int
pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
pcap_open_live = _lib.pcap_open_live
pcap_open_live.restype = POINTER(c_void_p)
pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
pcap_sendpacket = _lib.pcap_sendpacket
pcap_sendpacket.restype = c_int
pcap_sendpacket.argtypes = [POINTER(c_void_p), POINTER(c_ubyte), c_int]
pcap_close = _lib.pcap_close
pcap_close.restype = None
pcap_close.argtypes = [POINTER(c_void_p)]
pcap_geterr = _lib.pcap_geterr
pcap_geterr.restype = c_char_p
pcap_geterr.argtypes = [POINTER(c_void_p)]
pcap_next_ex = _lib.pcap_next_ex
pcap_next_ex.restype = c_int
pcap_next_ex.argtypes = [POINTER(c_void_p), POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_ubyte))]
iDiscoverTimeout = 2

# CREATION DES FONCTIONS ######################################################################################################################################

def banniere():
    print(couleur.jaune + "############################################################################################################")
    print(couleur.jaune + "#                                                                                                          #")
    print(couleur.fin +"")
    print(
        couleur.cyan + "        ██████╗   ██████╗  ██████╗ " + couleur.cyanfonce + "       ██████╗   ██████╗  ██╗  ██╗   ██████╗    ██████╗   ██╗     ")
    print(
        couleur.cyan + "       ██╔════╝  ██╔════╝  ██╔══██╗" + couleur.cyanfonce + "      ██╔════╝  ██╔════╝  ██║  ██║  ██╔═══██╗  ██╔═══██╗  ██║     ")
    print(
        couleur.cyan + "       ██║       ███████╗  ██████╔╝" + couleur.cyanfonce + "      ███████╗  ██║       ███████║  ██║   ██║  ██║   ██║  ██║     ")
    print(
        couleur.cyan + "       ██║       ╚════██║  ██╔══██╗" + couleur.cyanfonce + "      ╚════██║  ██║       ██╔══██║  ██║   ██║  ██║   ██║  ██║     ")
    print(
        couleur.cyan + "       ╚██████╗  ███████║  ██████╔╝" + couleur.cyanfonce + " ██╗  ███████║  ╚██████╗  ██║  ██║  ╚██████╔╝  ╚██████╔╝  ███████╗")
    print(
        couleur.cyan + "        ╚═════╝  ╚══════╝  ╚═════╝ " + couleur.cyanfonce + " ╚═╝  ╚══════╝   ╚═════╝  ╚═╝  ╚═╝   ╚═════╝    ╚═════╝   ╚══════╝")

    print("")
    print(couleur.blanc + "                                     ██████╗  ███████╗  ██████╗ " + couleur.rouge + "  ██╗ ")
    print(couleur.blanc + "                                    ██╔════╝  ██╔════╝  ╚════██╗" + couleur.rouge + "  ██║ ")
    print(couleur.blanc + "                                    ███████╗  ███████╗   █████╔╝" + couleur.rouge + "  ██║ ")
    print(couleur.blanc + "                                    ╚════██║  ██╔════╝  ██╔═══╝ " + couleur.rouge + "  ██║ ")
    print(couleur.blanc + "                                    ███████║  ██║       ███████╗" + couleur.rouge + "  ██║ ")
    print(couleur.blanc + "                                    ╚══════╝  ╚═╝       ╚══════╝" + couleur.rouge + "  ╚═╝ ")
    print("")
    print(couleur.jaune + "                                          --- Profinet Scanner --- ")
    print(couleur.jaune + "                                           --- Siemens Hacker --- ")
    print(couleur.fin +"")
    print(couleur.jaune + "#                                                                                                          #")
    print(couleur.jaune + "############################################################################################################")
    print(couleur.fin + "")                                                      
                                                       

def getAllInterfaces():
    def addToArr(array, adapter, ip, mac, device, winguid):
        if len(mac) == 17: # Lorsqu'il n'y a pas de MAC.
            array.append([adapter, ip, mac, device, winguid])
        return array

    # Retourne un tableau bi-dimmensionnel de chaque interface.
    # [0] = nom de l'interface (ex: Ethernet or eth0)
    # [1] = adresse IP (ex: 192.168.0.2)
    # [2] = adresse MAC (ex: ff:ee:dd:cc:bb:aa)
    # [3] = nom de l'interface (ex: Intel 82575LM, seulement sur Windows)
    # [4] = GUID (ex: {875F7EDB-CA23-435E-8E9E-DFC9E3314C55}, seulement sur Windows)
    interfaces=[]
    if os.name == 'nt': # Si Windows
        proc=Popen("getmac /NH /V /FO csv | FINDSTR /V disconnected", shell=True, stdout=PIPE)
        for interface in proc.stdout.readlines():
            intarr = interface.decode().split(',')
            adapter = intarr[0].replace('"','')
            devicename = intarr[1].replace('"','')
            mac = intarr[2].replace('"','').lower().replace('-',':')
            winguid = intarr[3].replace('"','').replace('\n', ''). replace('\r', '')[-38:]
            proc = Popen('netsh int ip show addr "' + adapter + '" | FINDSTR /I IP', shell=True, stdout=PIPE)
            try: ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', proc.stdout.readlines()[0].decode(errors='ignore').replace(' ',''))[0]
            except: ip = ''
            interfaces=addToArr(interfaces, adapter, ip, mac, devicename, winguid)

    else: # Si Linux
        proc=Popen("for i in $(ip address | grep -v \"lo\" | grep \"default\" | cut -d\":\" -f2 | cut -d\" \" -f2);do echo $i $(ip address show dev $i | grep \"inet \" | cut -d\" \" -f6 | cut -d\"/\" -f1) $(ip address show dev $i | grep \"ether\" | cut -d\" \" -f6);done", shell=True, stdout=PIPE)
        for interface in proc.stdout.readlines():
            intarr = interface.decode().split(' ')
            if len(intarr)<3: continue ## Device has no MAC address, L2 scanning not an option
            interfaces = addToArr(interfaces, intarr[0], intarr[1], intarr[2].replace('\n',''), '', '')

    return interfaces

# Liste de tous les adaptateurs NPF et recherche de celui qui possède le nom de périphérique Windows (\Device\NPF_{GUID})
def findMatchingNPFDevice(windevicename):
    alldevs = POINTER(pcap_if)()
    bufErrbuf = create_string_buffer(256)
    if pcap_findalldevs(byref(alldevs), bufErrbuf) == -1:
        print("Erreur dans pcap. %s\n" % bufErrbuf.value)
        sys.exit(1)
    pcapdevices = alldevs.contents
    while pcapdevices:
        if str(pcapdevices.description) == windevicename:
            return pcapdevices.name
        if pcapdevices.next:
            pcapdevices = pcapdevices.next.contents
        else:
            pcapdevices = False
    return ''

def createPacket(sData):
    bHexData = unhexlify(sData)
    arrBytePacket = (c_ubyte * len(bHexData))()
    b = bytearray()
    b.extend(bHexData)
    for i in range(0,len(bHexData)): arrBytePacket[i] = b[i]
    return arrBytePacket

def sendRawPacket(bNpfdevice, sEthertype, sSrcmac, boolSetNetwork = False, sNetworkDataToSet = '', sDstmac = ''):
    if sEthertype == '88cc': # Paquets LLDP.
        sDstmac = '0180c200000e'
        sData = '0210077365727665722d6e6574776f726b6d040907706f72742d303031060200140a0f5345525645522d4e4554574f524b4d0c60564d776172652c20496e632e20564d77617265205669727475616c20506c6174666f726d2c4e6f6e652c564d776172652d34322033362036642039622034302062642038642038302d66302037362061312066302035332030392039352032370e040080008010140501ac101e660200000001082b0601040181c06efe08000ecf0200000000fe0a000ecf05005056b6feb6fe0900120f0103ec0300000000'
    elif sEthertype == '8100': # Paquets PN-DCP, Profinet Discovery Packet, sEthertype '8100'.
        sDstmac = '010ecf000000'
        sData = '00008892fefe05000400000300800004ffff00000000000000000000000000000000000000000000000000000000'
    elif sEthertype == '8892' and boolSetNetwork:        
        sData = ('fefd 04 00 04000001 0000 0012 0102 000e 0001' + sNetworkDataToSet + '0000 0000 0000 0000 0000 0000').replace(' ','') 
    elif sEthertype == '8892' and not boolSetNetwork:        
        sData = sNetworkDataToSet

    # Obtenir les paquets.
    arrBytePacket = createPacket(sDstmac + sSrcmac + sEthertype + sData)

    # Envoyer les paquets.
    bufErrbuf = create_string_buffer(256)
    handlePcapDev = pcap_open_live(bNpfdevice, 65535, 1, 1000, bufErrbuf) 
    if not bool(handlePcapDev):
        print("\nErreur : utiliser le mode SUDO\n")        
        sys.exit(1)

    if pcap_sendpacket(handlePcapDev, arrBytePacket, len(arrBytePacket)) != 0:
        print("\nErreur d'envoie de paquet %s\n" % pcap_geterr(handlePcapDev))
        sys.exit(1)

    pcap_close(handlePcapDev)
    return arrBytePacket

# Réception des paquets.
def receiveRawPackets(bNpfdevice, iTimeout, sSrcmac, sEthertype, stopOnReceive = False):
    arrReceivedRawData = []
    bufErrbuf = create_string_buffer(256)
    handlePcapDev = pcap_open_live(bNpfdevice, 65535, 1, 1000, bufErrbuf) 
    if not bool(handlePcapDev):
        print("\nUtilisation de l'adaptateur {} non supporté par Pcap\n".format(bNpfdevice))
        sys.exit(1)

    ptrHeader = POINTER(pcap_pkthdr)()
    ptrPktData = POINTER(c_ubyte)()
    iReceivedpacket = pcap_next_ex(handlePcapDev, byref(ptrHeader), byref(ptrPktData))    
    flTimer = time.time() + int(iTimeout)
    i = 0
    while iReceivedpacket >= 0:
        iTimeleft = int(round(flTimer - time.time(), 0))
        status("Paquets reçus: %s, temps restant: %i  \r" % (str(i), iTimeleft))
        if iTimeleft <= 0: break 
        lstRawdata = ptrPktData[0:ptrHeader.contents.len]
        sPackettype = hexlify(bytearray(lstRawdata[12:14])).decode().lower()
        sTargetmac = hexlify(bytearray(lstRawdata[:6])).decode().lower()
        if sPackettype == sEthertype.lower() and sSrcmac.lower() == sTargetmac:            
            arrReceivedRawData.append(lstRawdata)
            if stopOnReceive: break
        
        iReceivedpacket = pcap_next_ex(handlePcapDev, byref(ptrHeader), byref(ptrPktData))
        i += 1
    pcap_close(handlePcapDev)
    return arrReceivedRawData

# Découpage des données récupérées.
def parseResponse(sHexdata, sMac):
    arrDevice = {}
    arrDevice['mac_address'] = sMac
    arrDevice['type_of_station'] = 'None'
    arrDevice['name_of_station'] = 'None'
    arrDevice['vendor_id'] = 'None'
    arrDevice['device_id'] = 'None'
    arrDevice['device_role'] = 'None'
    arrDevice['ip_address'] = 'None'
    arrDevice['subnet_mask'] = 'None'
    arrDevice['standard_gateway'] = 'None'
    arrDevice['hardware'] = None
    arrDevice['firmware'] = None
    
    if not str(sHexdata[:4]).lower() == 'feff':
        print("Erreur : ce n'est pas une réponse DCP cohérente")
        return arrDevice
    
    dataToParse = sHexdata[24:] 
    while len(dataToParse) > 0:        
        blockLength = int(dataToParse[2*2:4*2], 16)
        block = dataToParse[:(4 + blockLength)*2]
        
        blockID = str(block[:2*2])
        if blockID == '0201':
            arrDevice['type_of_station'] = str(unhexlify(block[4*2:4*2 + blockLength*2]))[2:-1].replace(r'\x00','')
        elif blockID == '0202':
            arrDevice['name_of_station'] = str(unhexlify(block[4*2:4*2 + blockLength*2]))[2:-1].replace(r'\x00','')
        elif blockID == '0203':
            arrDevice['vendor_id'] = str(block[6*2:8*2])
            arrDevice['device_id'] = str(block[8*2:10*2])
        elif blockID == '0204':
            arrDevice['device_role'] = str(block[6*2:7*2])
            devrole = ''
            
        elif blockID == '0102':
            arrDevice['ip_address'] = socket.inet_ntoa(struct.pack(">L", int(block[6*2:10*2], 16)))
            arrDevice['subnet_mask'] = socket.inet_ntoa(struct.pack(">L", int(block[10*2:14*2], 16)))
            arrDevice['standard_gateway'] = socket.inet_ntoa(struct.pack(">L", int(block[14*2:18*2], 16)))        
        
        padding = blockLength%2 
        dataToParse = dataToParse[(4 + blockLength + padding)*2:]
        
    return arrDevice
        
def status(msg):
    sys.stderr.write(msg)
    sys.stderr.flush()

def endIt(sMessage=''):
    print()
    if sMessage: print("Message d'erreur : "+sMessage)
    print("Terminé.")
    input("Presser Entrée pour continuer...")
    sys.exit()

def scanPort(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) 
    try:
        sock.connect((ip, port))
        sock.close()
    except:
        return ''
    return port

def tcpScan(device):
    openports = []
    if scanPort(device['ip_address'], 102) == 102: openports.append(102)
    if scanPort(device['ip_address'], 502) == 502: openports.append(502)
    device['open_ports'] = openports
    return device

def getInfo(device):
    os.system('cls' if os.name == 'nt' else 'clear')
    banniere()    
    vendorid = 'ID inconnu'
    devid = 'ID inconnu'
    devrole = ''
    if device['vendor_id'] == '002a': vendorid = 'Siemens'
    if device['device_id'] == '0a01': devid = 'Switch'
    elif device['device_id'] == '0202': devid = 'PCSIM'
    elif device['device_id'] == '0203': devid = 'S7-300 CP'
    elif device['device_id'] == '0101': devid = 'S7-300'
    elif device['device_id'] == '010d': devid = 'S7-1200'
    elif device['device_id'] == '0301': devid = 'HMI'
    elif device['device_id'] == '0403': devid = 'HMI'
    elif device['device_id'] == '010b': devid = 'ET200S'
    elif device['device_id'] == '010e': devid = 'S7-1500'
    else: devid = ''
    try:
        binresult = bin(int(device['device_role'], 16))[2:]
        if int(binresult) & 1 == 1: devrole += 'IO-Device '
        if int(binresult) & 10 == 10: devrole += 'IO-Controller '
        if int(binresult) & 100 == 100: devrole += 'IO-Multidevice '
        if int(binresult) & 1000 == 1000: devrole += 'PN-Supervisor '
    except:
        devrole = ''
    print("INFORMATION DE L'APPAREIL :")
    print("Adresse MAC:           " + device['mac_address'])
    print("Type de station:       " + device['type_of_station'])
    print("Nom de la station:     " + device['name_of_station'])
    print("Code Vendor:           " + device['vendor_id'] + ' (decoded: ' + vendorid + ')')
    print("ID Produit:            " + device['device_id'] + ' (decoded: ' + devid + ')')
    print("Rôle:                  " + device['device_role'] + '   (decoded: ' + devrole + ')')
    print("Adresse IP:            " + device['ip_address'])
    print("Masque de sous-réseau: " + device['subnet_mask'])
    print("Passerelle:            " + device['standard_gateway'])
    print("")
    getInfoViaCOTP(device)
    print("")
    print(" --> Etat de l'appareil : " + getCPU(device) + "\n")
    input("Presser Entrée pour revenir au menu...")
    return device

def isIpv4(ip):
    if ip == '0.0.0.0': return True
    match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
    if not match:
        return False
    quad = []
    for number in match.groups():
        quad.append(int(number))
    if quad[0] < 1:
        return False
    for number in quad:
        if number > 255 or number < 0:
            return False
    return True

def setNetwork(device, npfdevice, srcmac):
    def ipToHex(ipstr):
        iphexstr = ''
        for s in ipstr.split('.'):
            if len(hex(int(s))[2:]) == 1:
                iphexstr += '0'
            iphexstr += str(hex(int(s))[2:])
        return iphexstr
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print("CONFIGURATION RESEAU DE L'APPAREIL : ")
    newip = input("Donner la nouvelle adresse IP [" + device['ip_address'] + "]     : ")
    if newip == '': newip = device['ip_address']
    newsnm = input("Donner le nouveau masque de sous-réseau [" + device['subnet_mask'] +"]    : ")
    if newsnm == '': newsnm = device['subnet_mask']
    newgw = input("Donner l'adresse de la passerelle [" + device['standard_gateway'] + "]: ")
    if newgw == '': newgw = device['standard_gateway']
    if not isIpv4(newip) or not isIpv4(newsnm) or not isIpv4(newgw):
        print("Une ou plusieurs adresses sont erronées. \nCe référer à la RFC791.")
        input('')
        return device
    networkdata = ipToHex(newip) + ipToHex(newsnm) + ipToHex(newgw)
    print("Veuillez patienter pendant la construction du paquet...")
    print()
    
    scan_response = ''
    pool = ThreadPool(processes=1)
    async_result = pool.apply_async(receiveRawPackets, (npfdevice, iDiscoverTimeout, srcmac, '8892', True))    

    # Envoie du paquet.
    sendRawPacket(npfdevice, '8892', srcmac, True, networkdata, device['mac_address'].replace(':', ''))
    time.sleep(1) # Wait for response to return

    # Vérification de la réponse.
    bResult = async_result.get()
    if len(bResult)>0: 
        data = hexlify(bytearray(bResult[0]))[28:].decode(errors='ignore')
        responsecode = data[36:40]
        if responsecode == '0000':
            print("Les nouvelles données du réseau ont été définies avec succès !                     ")
            device['ip_address'] = newip
            device['subnet_mask'] = newsnm
            device['standard_gateway'] = newgw
        elif responsecode == '0600':
            print("Erreur dans le paramétrage des données réseau : appareil en fonctionnement.       ")
        elif responsecode == '0300':
            print("Erreur dans le paramétrage.  ")
        else:
            print("Réponse non définie (" + responsecode + "), please investigate.        ")
    else: print("\nFonction non implémentée")
    
    input("Presser Entrée pour revenir au menu...")
    return device

def setStationName(device, npfdevice, srcmac):
    os.system('cls' if os.name == 'nt' else 'clear')
    print("NOM PROFINET DE L'APPAREIL :")
    print("Attention: Seul les minuscules et les symboles \'.\' and \'-\' sont autorisés")
    newname = input("Indiquer le nouveau nom ["+device['name_of_station']+"]     : ")
    if newname == '': newname = device['name_of_station']    
    
    scan_response = ''
    pool = ThreadPool(processes=1)
    async_result = pool.apply_async(receiveRawPackets, (npfdevice, iDiscoverTimeout, srcmac, '8892', True))
    time.sleep(1) 
    
    nname=hexlify(newname.lower().encode()).decode(errors='ignore')
    namelength=int(len(nname)/2)
    padding = ''
    if namelength%2 == 1: padding = '00'
    firstDCP = hex(namelength+(int(len(padding)/2))+6)[2:]
    if len(firstDCP) == 1: firstDCP='000'+firstDCP
    if len(firstDCP) == 2: firstDCP='00'+firstDCP
    if len(firstDCP) == 3: firstDCP='0'+firstDCP
    secondDCP = hex(namelength+2)[2:]
    if len(secondDCP) == 1: secondDCP='000'+secondDCP
    if len(secondDCP) == 2: secondDCP='00'+secondDCP
    if len(secondDCP) == 3: secondDCP='0'+secondDCP
    data='fefd 04 00 02010004 0000'    
    data+=firstDCP
    data+='02 02'    
    data+=secondDCP
    data+='0001'    
    data+=nname+padding
    data+='00000000000000000000000000000000' 
    
    sendRawPacket(npfdevice, '8892', srcmac, False, data.replace(' ',''), device['mac_address'].replace(':', ''))
    
    bResult = async_result.get()
    if len(bResult)>0: 
        data = hexlify(bytearray(bResult[0]))[28:].decode(errors='ignore')
        responsecode = data[36:38]
        if responsecode == '00':
            print("Le nouveau nom de l'appareil a été défini avec succès sur "+newname)
            device['name_of_station']=newname
        elif responsecode == '03':
            print("Erreur dans la définition du nom de l'appareil : Nom non accepté ou non défini dans le projet.")
            print(data)
    else: print("\nAucune réponse...")

    input("Presser Entrée pour revenir au menu...")
    return device

def send_and_recv(sock, strdata, sendOnly = False):
    data = unhexlify(strdata.replace(' ','').lower())
    sock.send(data)
    if sendOnly: return
    ret = sock.recv(65000)
    return ret

def getS7GetCoils(ip):
    def printData(sWhat, s7Response): 
        if not s7Response[18:20] == '00': print("Une erreur s'est produite lors de la configuration S7Comm : " + str(s7Response) + "\n")
        s7Data = s7Response[14:]
        datalength = int(s7Data[16:20], 16) 
        s7Items = s7Data[28:28 + datalength*2]
        if not s7Items[:2] == 'ff':
            print("Une erreur s'est produite lors de la lecture des données S7Comm : " + str(s7Data) + "\nFirmware non supporté ?\n")
            return False
    
        print('     ###--- ' + sWhat + ' ---###')
        sToShow = [''] * 8
        for i in range(0, 6):
            iOffset1 = (4 - i) * -2
            iOffset2 = iOffset1 + 2
            if iOffset2 == 0: iOffset2 = None
            iData = int(s7Items[iOffset1:iOffset2], 16) 

            for j in range(0,8):                
                bVal = iData & int(2**j)
                if not bVal == 0: bVal = 1
                sToShow[j] = sToShow[j] +  str(i) + '.' + str(j) + ': ' + str(bVal) + ' | ' 
        for i in range(0,8): print(sToShow[i][:-2])
        print()
        return True

    sock = setupConnection(ip, 102)
    
    s7Response = hexlify(send_and_recv(sock, '0300001f' + '02f080' + '32010000732f000e00000401120a10 06 00010000 81 000000'.replace(' ',''))).decode(errors='ignore')
    if not printData('Inputs',s7Response): return False
    
    s7Response = hexlify(send_and_recv(sock, '0300001f' + '02f080' + '32010000732f000e00000401120a10 06 00010000 82 000000'.replace(' ',''))).decode(errors='ignore')
    if not printData('Outputs',s7Response): return False

    s7Response = hexlify(send_and_recv(sock, '0300001f' + '02f080' + '32010000732f000e00000401120a10 06 00010000 83 000000'.replace(' ',''))).decode(errors='ignore')
    if not printData('Merkers',s7Response): return False
    sock.close()
    return True

def setupConnection(sIP, iPort):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    sock.connect((sIP, iPort))    
    cotpsync = hexlify(send_and_recv(sock, '03000016' + '11e00000000100c0010ac1020100c2020101')).decode(errors='ignore')
    if not cotpsync[10:12] == 'd0': finish('COTP Sync failed, PLC not reachable?')    
    s7comsetup = hexlify(send_and_recv(sock, '03000019' + '02f080' + '32010000722f00080000f0000001000101e0')).decode(errors='ignore')
    if not s7comsetup[18:20] == '00': finish('Some error occured with S7Comm setup, full data: ' + s7comsetup)
    return sock

def setOutputs(sIP, iPort, sOutputs):
    if sOutputs == '' or len(sOutputs) > 8: sOutputs = '0'    
    sOutputs = sOutputs[::-1]   
    hexstring = hex(int(sOutputs, 2))[2:]
    if len(hexstring) == 1: hexstring = '0' + hexstring 
    
    sock = setupConnection(sIP, iPort)
    
    s7Response = hexlify(send_and_recv(sock, '03000024' + '02f080' + '32010000732f000e00050501120a1002000100008200000000040008' + hexstring)).decode(errors='ignore')
    if s7Response[-2:] == 'ff': print("Sortie(s) forcée(s) avec succès.")
    else: print("Erreur de forçage des sorties.")
    sock.close()

def setMerkers(sIP, iPort, sMerkers, iMerkerOffset=0):    
    sMerkers = sMerkers[::-1]    
    hexstring = hex(int(sMerkers, 2))[2:]
    if len(hexstring) == 1: hexstring = '0' + hexstring     
    
    sock = setupConnection(sIP, iPort)
    
    sMerkerOffset = bin(iMerkerOffset)
    sMerkerOffset = sMerkerOffset + '000'
    hMerkerOffset = str(hex(int(sMerkerOffset[2:],2)))[2:]
    hMerkerOffset = hMerkerOffset.zfill(6) ## Add leading zero's up to 6
    print('Sending '+hexstring+' using offset '+hMerkerOffset)

    s7Response = hexlify(send_and_recv(sock, '03000025' + '02f080' + '320100001500000e00060501120a100400010000 83 ' + hMerkerOffset + '00 04 0010' + hexstring + '00')).decode(errors='ignore')
    if s7Response[-2:] == 'ff': print("Ecriture des mémentos validée.")
    else: print("Erreur d'écriture des mémentos.")
    sock.close()

def manageOutputs(device):
    os.system('cls' if os.name == 'nt' else 'clear')    
    status = ''
    while True:
        ports = []
        boolAlive = False
        print("PARAMETRER LES SORTIES :")
        if status != '':
            print('## --> ' + status)
            status = ''
        print()
        try: 
            ports = device['open_ports']
        except:
            print("Scanner d'abord l'appareil...")
            device = tcpScan(device)
            ports = device['open_ports']
        if len(ports) == 0: return 1
        for port in ports:
            if port == 102:
                print("S7Comm détecté, lecture des sorties...")
                boolAlive = getS7GetCoils(device['ip_address'])
                if boolAlive:
                    ans = input("Voulez-vous modifier les sorties, les mémentos ou Non ? [o/m/N]: ").lower()
                    if ans == 'o':
                        array = input("Quelle(s) sortie(s) voulez-vous modifier ? [00000000]: ")
                        setOutputs(device['ip_address'], 102, array)
                        status = "La modification des sorties a été envoyé à l'appareil..."
                    if ans == 'm':
                        array = input("Quel(s) mémento(s) voulez-vous modifier [00000000,0]: ")
                        offset = int(array.split(',')[1])
                        array = array.split(',')[0]
                        setMerkers(device['ip_address'], 102, array, offset)
                        status = "La modification des mémentos a été envoyé à l'appareil..."
                    
                    if ans == 'n' or ans == '': return 0
                else: break
        if not boolAlive: break
    input("Presser sur Entrée pour revenir au menu.")

def flashLED(device, srcmac):
    sDuration = input("Combien de temps voulez-vous faire clignoter la LED (en seconde) ?")
    iDuration = 2
    if sDuration.isdigit(): iDuration = int(sDuration)
    runLoop = True
    i = 0
    while runLoop:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("CLIGNOTEMENT DE LA LED D'IDENTIFICATION :")
        print("Clignotement de la LED " + device['name_of_station'] + ", " + str(i) + " pendant " + str(iDuration) +  " secondes.")
        
        data='fefd 040000001912000000080503000400000100 000000000000000000000000000000000000000000000000000000000000'
        sendRawPacket(bNpfdevice, '8892', srcmac, False, data.replace(' ',''), device['mac_address'].replace(':', ''))
        
        i += 2
        if i > iDuration: runLoop = False
        time.sleep(2)
        
        
def getInfoViaCOTP(device):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) 
    try:
        sock.connect((device['ip_address'], 102)) 
    except:
        print('No route to IP ' + device['ip_address'])
        return
    cotpconnectresponse = hexlify(send_and_recv(sock, '03000016'+'11e00000000500c1020600c2020600c0010a')).decode(errors='ignore')
    if not cotpconnectresponse[10:12] == 'd0':
        print("Erreur de requête COTP, adresse IP introuvable "+device['ip_address']+"?")
        return

    data = '720100b131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3816900151653657276657253657373696f6e5f3742363743433341a3822100150b313a3a3a362e303a3a3a12a3822800150d4f4d532b204465627567676572a38229001500a3822a001500a3822b00048480808000a3822c001211e1a304a3822d001500a1000000d3817f0000a38169001515537562736372697074696f6e436f6e7461696e6572a2a20000000072010000'
    tpktlength = str(hex(int((len(data)+14)/2)))[2:] 
    cotpdata = send_and_recv(sock, '030000'+tpktlength+'02f080'+data).decode(errors='ignore')    
    
    if len(cotpdata.split(';')) >= 4:
        sHardware = cotpdata.split(';')[2]
        sFirmware = ''.join(list(filter(lambda x: x in string.printable, cotpdata.split(';')[3].replace('@','.'))))
        print('Hardware: ' + sHardware)
        print('Firmware: ' + sFirmware)
        device['hardware'] = sHardware
        device['firmware'] = sFirmware

    sock.close()
    return device

def manageCPU(device):
    runLoop = True
    boolWorked = True
    while runLoop:
        os.system('cls' if os.name == 'nt' else 'clear')
        if not boolWorked: print("Le changement de mode a échoué")
        print("MODIFICATION DE L'ETAT DE L'APPAREIL\n")
        print("Etat de la CPU actuel : "+getCPU(device))
        ans = input("Voulez-vous inverser l'état de la CPU [o/n]: ").lower()
        if ans == 'o':
            print("Veuillez attendre quelques secondes...")
            boolWorked = changeCPU(device)
        else:
            runLoop = False
        

def getCPU(device):
    sState = 'Running'
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) # 1 second timeout
    try:
        sock.connect((device['ip_address'], 102))
    except:
        return 'Unknown'
    
    cotpconnectresponse = hexlify(send_and_recv(sock, '03000016'+'11e00000001d00c1020100c2020100c0010a')).decode(errors='ignore')    
    if not cotpconnectresponse[10:12] == 'd0':
        print('COTP Connection Request failed')
        return ''
    
    s7setupdata='32010000020000080000'+'f0000001000101e0'
    tpktlength = str(hex(int((len(s7setupdata)+14)/2)))[2:]
    s7setup = send_and_recv(sock, '030000'+tpktlength+'02f080'+s7setupdata)
    ##---- S7 Request CPU -----------
    s7readdata = '3207000005000008 000800011204 11440100ff09000404240001'
    tpktlength = str(hex(int((len(s7readdata.replace(' ',''))+14)/2)))[2:]
    s7read = send_and_recv(sock,'030000'+tpktlength+'02f080'+s7readdata)
    if hexlify(s7read[44:45]).decode(errors='ignore') == '03': sState = 'Stopped'
    sock.close()
    return sState

def changeCPU(device):
    curState = getCPU(device)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    sock.connect((device['ip_address'], 102))     
    send_and_recv(sock,'03000016'+'11e00000002500c1020600c2020600c0010a')    
    sResp = hexlify(send_and_recv(sock,'030000c0'+'02f080'+'720100b131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3816900151653657276657253657373696f6e5f4536463534383534a3822100150b313a3a3a362e303a3a3a12a3822800150d4f4d532b204465627567676572a38229001500a3822a001500a3822b00048480808000a3822c001211e1a300a3822d001500a1000000d3817f0000a38169001515537562736372697074696f6e436f6e7461696e6572a2a20000000072010000')).decode(errors='ignore')
    sSID = str(hex(int('0'+sResp[48:50],16)+int('80',16))).replace('0x','')
    if len(sSID)%2 == 1:  sSID = '0' + sSID    
    if curState == 'Stopped': 
        send_and_recv(sock,'03000078'+'02f080'+'72020069310000054200000003000003'+sSID+'34000003 ce 010182320100170000013a823b00048140823c00048140823d000400823e00048480c040823f0015008240001506323b313035388241000300030000000004e88969001200000000896a001300896b000400000000000072020000')
    else:
        send_and_recv(sock,'03000078'+'02f080'+'72020069310000054200000003000003'+sSID+'34000003 88 010182320100170000013a823b00048140823c00048140823d000400823e00048480c040823f0015008240001506323b313035388241000300030000000004e88969001200000000896a001300896b000400000000000072020000')
    send_and_recv(sock,'0300002b'+'02f080'+'7202001c31000004bb00000005000003'+sSID+'34000000010000000000000000000072020000')
    send_and_recv(sock,'0300002b'+'02f080'+'7202001c31000004bb00000006000003'+sSID+'34000000020001010000000000000072020000')
    runloop = True
    print("Réception des données")
    while runloop:
        try: response = sock.recv(65000)
        except: runloop = False
    try:
        send_and_recv(sock,'03000042'+'02f080'+'7202003331000004fc00000007000003'+sSID+'360000003402913d9b1e000004e88969001200000000896a001300896b00040000000000000072020000')
    except:
        sock.close()
        return False
    if curState == 'Stopped': ## Will perform start
        send_and_recv(sock,'03000043'+'02f080'+'7202003431000004f200000008000003'+sSID+'36000000340190770008 03 000004e88969001200000000896a001300896b00040000000000000072020000')
    else:
        send_and_recv(sock,'03000043'+'02f080'+'7202003431000004f200000008000003'+sSID+'36000000340190770008 01 000004e88969001200000000896a001300896b00040000000000000072020000')
    send_and_recv(sock,'0300003d'+'02f080'+'7202002e31000004d40000000a000003'+sSID+'34000003d000000004e88969001200000000896a001300896b000400000000000072020000')
    
    sock.close()
    return True

def scanNetwork(sAdapter, sMacaddr, sWinguid):    
    if os.name == 'nt': sAdapter = r'\Device\NPF_' + sWinguid    
    bNpfdevice = sAdapter.encode()
    
    print("Construction du paquet...")
    
    packet = sendRawPacket(bNpfdevice, '8100', sMacaddr)
    print("\nLe paquet est envoyé (" + str(len(packet)) + " octets)")
    
    print("\nReception des paquets " + str(iDiscoverTimeout) + " secondes ...\n")
    receivedDataArr = receiveRawPackets(bNpfdevice, iDiscoverTimeout, sMacaddr, '8892')
    print()
    print("\nSauvegarde des " + str(len(receivedDataArr)) + " paquets")
    print()
    return receivedDataArr, bNpfdevice

def parseData(receivedDataArr):    
    lstDevices = []
    for packet in receivedDataArr:
        sHexdata = hexlify(bytearray(packet))[28:].decode(errors='ignore')         
        sMac = ':'.join(re.findall('(?s).{,2}', str(hexlify(bytearray(packet)).decode(errors='ignore')[6*2:12*2])))[:-1]
        arrResult = parseResponse(sHexdata, sMac)
        lstDevices.append(arrResult)
        
    return lstDevices

def addDevice():
    sIP = input("Entrez l'adresse IP du nouvel appareil :")
    return {
        'mac_address':'UNK',
        'type_of_station':'None',
        'name_of_station':'None',
        'vendor_id':'None',
        'device_id':'None',
        'device_role':'None',
        'ip_address':sIP,
        'subnet_mask':'None',
        'standard_gateway':'None',
        'hardware':'None',
        'firmware':'None'
    }
    
arrInterfaces = getAllInterfaces()
if len(getAllInterfaces()) > 1:
    for iNr, arrInterface in enumerate(arrInterfaces): print('[' + str(iNr + 1) + '] ' + arrInterface[2] + ' has ' + arrInterface[1] + ' (' + arrInterface[0] + ')')
    print("[Q] Quitter")
    sAnswer1 = input("Sélectionner la carte réseau [1]: ").lower()
    if sAnswer1 == 'q': sys.exit()
    if sAnswer1 == '' or not sAnswer1.isdigit() or int(sAnswer1) > len(arrInterfaces): sAnswer1 = 1
else:
    sAnswer1 = 1

sAdapter = arrInterfaces[int(sAnswer1) - 1][0]                  # ex: 'Ethernet 2'
sMacaddr = arrInterfaces[int(sAnswer1) - 1][2].replace(':', '') # ex: 'ab58e0ff585a'
sWinguid = arrInterfaces[int(sAnswer1) - 1][4]                  # ex: '{875F7EDB-CA23-435E-8E9E-DFC9E3314C55}'

receivedDataArr, bNpfdevice = scanNetwork(sAdapter, sMacaddr, sWinguid)

lstDevices = parseData(receivedDataArr)

# BOUCLE PRINCIPALE ###########################################################################################################################################
while True:
    os.system('cls' if os.name == 'nt' else 'clear')
    banniere()
    print(couleur.blanc +"                        LISTE DES APPAREILS :"+ couleur.fin)
    print("")
    for iNr, arrDevice in enumerate(lstDevices):
        print(couleur.vert + "[" + str(iNr + 1).zfill(2) + "]"  + arrDevice['mac_address'] + " (" + arrDevice['ip_address'] + ", "+ arrDevice['type_of_station'] + ", " + arrDevice['name_of_station'] + ") " + couleur.fin)
    print(couleur.cyan + "[A] Ajouter un appareil par l'IP")
    print(couleur.cyan + "[R] Re-scanner")
    print(couleur.rouge +"[Q] Quitter" + couleur.fin)
    sAnswer2 = input("Sélectionner l'option voulue [1]: ").lower()
    if sAnswer2 == 'q':
        sys.exit()
    elif sAnswer2 == 'r':
        receivedDataArr, bNpfdevice = scanNetwork(sAdapter, sMacaddr, sWinguid)
        parseData(receivedDataArr)
        continue
    elif sAnswer2 == 'a':
        device = addDevice()
    else:
        if sAnswer2 == '' or not sAnswer2.isdigit() or int(sAnswer2) > len(lstDevices): sAnswer2 = 1
        device = lstDevices[int(sAnswer2)-1]    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        banniere()
        print(couleur.blanc + "                            MENU PRINCIPAL :" + couleur.fin)
        print("")
        print(couleur.jaune + "[1]" + couleur.vert + " Configurer l'adresse IP de l'appareil")
        print(couleur.jaune + "[2]" + couleur.vert + " Configurer le nom de l'appareil")
        print(couleur.jaune + "[3]" + couleur.vert + " Lire les informations de l'appareil")
        print(couleur.jaune + "[4]" + couleur.vert + " Faire clignoter la LED d'identification de l'appareil")
        print("")
        print(couleur.jaune + "[5]" + couleur.cyan + " Changer l'état de la CPU (Start/Stop)")
        print("")
        print(couleur.jaune + "[6]" + couleur.cyan + " Afficher/Modifier les sorties de la CPU")
        print("")
        print(couleur.jaune + "[O]" + couleur.cyan + " Choisir un autre appareil")
        print(couleur.jaune + "[Q]" + couleur.rouge + " Quitter\n" + couleur.fin)
        sAnswer3 = input("Selectionner l'action à effectuer sur {} ({}) [1]: ".format(device['ip_address'], device['name_of_station'])).lower()
        if sAnswer3 == 'q': sys.exit()
        if sAnswer3 == '3': device = getInfo(device)
        if sAnswer3 == '6': manageOutputs(device)
        if sAnswer3 == '5': manageCPU(device)
        if sAnswer3 == '4': flashLED(device, sMacaddr)
        if sAnswer3 == '2': setStationName(device, bNpfdevice, sMacaddr)
        if sAnswer3 == 'o': break
        if sAnswer3 == '1' or sAnswer3 == '':
            device = setNetwork(device, bNpfdevice, sMacaddr)
            lstDevices[int(sAnswer2)-1] = device