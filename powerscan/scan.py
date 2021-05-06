#!/usr/bin/python

# check dependencies
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, ICMP, UDP

try:
    # disable scapy warnings
    import logging
    import traceback

    logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

    # imports
    from optparse import OptionParser, OptionGroup
    from multiprocessing import Pool as ProcessPool
    from multiprocessing import Lock as ProcessLock
    from multiprocessing import Value, cpu_count
    from multiprocessing.dummy import Pool as ThreadPool
    from multiprocessing.dummy import Lock as ThreadLock
    from netaddr import IPNetwork as getAddrList
    from scapy.all import *
    from numpy import array_split
    import sys, socket, nmap, paramiko
    from os import system, geteuid
    from subprocess import check_call
    from time import time, sleep
    from random import randint
    from math import log
except Exception as e:
    # print missed module and sources of dependencies
    print("[!] " + str(e))
    print('Dependencies:')
    print(' ')
    print('   python version 2.7  - https://www.python.org/downloads/')
    print('   module scapy        - https://github.com/secdev/scapy.git')
    print('   module netaddr      - https://github.com/drkjam/netaddr.git')
    print('   module numpy        - https://github.com/numpy/numpy.git')
    print('   module paramiko     - https://github.com/paramiko/paramiko.git')
    print('   module python-nmap   - https://bitbucket.org/xael/python-nmap')
    print('   SYSTEM_PATH         - /dev/null')
    print(' ')

# init this as script var
this = sys.modules[__name__]

if this:
    # print color
    this.OKCYAN = '\033[36m'
    this.OKGREEN = '\033[92m'
    this.WARNING = '\033[93m'
    this.FAIL = '\033[91m'
    this.ENDC = '\033[0m'
    this.BOLD = '\033[1m'

# global vars
cur = None
curPercent = None
countServer = None
countOpen = None
once = None
PLOCK = None
TLOCK = None


def __start(hosts, processes):
    # init global vars
    # only variables that have to communicate
    # between different processes
    # anything else uses this
    global cur
    global curPercent
    global countServer
    global countOpen
    global once
    global PLOCK
    global TLOCK

    # define global vars
    cur = Value('i', 0)
    curPercent = Value('i', 0)
    countServer = Value('i', 0)
    countOpen = Value('i', 0)
    once = Value('i', 0)
    PLOCK = ProcessLock()
    TLOCK = ThreadLock()

    # define packet dictionary
    if this.amp == 1:
        this.packets = {}
        # define ampFactor dictionary
        this.factors = {}

    # timestamp before
    before = time()

    # split the host list in number of processes
    processHostArray = array_split(hosts, processes)

    # init process pool with initializer for global vars
    pPool = ProcessPool(processes=processes, initializer=__processValues,
                        initargs=(cur, curPercent, countServer, countOpen, once, PLOCK, TLOCK,))
    try:
        # start process pool
        pPool.map_async(__processing, processHostArray).get(9999999)
    except KeyboardInterrupt:
        if once.value == 0:
            once.value += 1
            print('\n\n[!] killing all python processes')
            # use pkill to make sure every process is killed
            os.system('pkill python')
            sys.exit(0)
    # close process pool
    pPool.close()
    pPool.join()

    # timestamp after
    after = time()

    # create new files for each port with 1 ip per line +\n
    # the standard output file will not be touched
    if this.amp == 0:
        __cleanFile(this.outFileName)
    else:
        __cleanFile('amp-' + this.outFileName)

    # print a finish statement dependent on verbose mode
    if this.verbose == 0:
        print('\n              ** Finished scan in ' + str(int(after - before)) + ' seconds. Found ' + str(
            countOpen.value) + ' open servers. **\n')
    else:
        print('[*] Finished scan in ' + str(int(after - before)) + ' seconds. Found ' + str(
            countOpen.value) + ' open servers.')


def __processValues(arg1, arg2, arg3, arg4, arg5, arg6, arg7):
    # init global vars
    global cur
    global curPercent
    global countServer
    global countOpen
    global once
    global TLOCK
    global PLOCK
    # give each process access to the value
    cur = arg1
    curPercent = arg2
    countServer = arg3
    countOpen = arg4
    once = arg5
    PLOCK = arg6
    TLOCK = arg7


def __processing(processArray):
    # init global vars
    global cur
    global curPercent
    global countServer
    global countOpen
    global once
    global PLOCK
    global TLOCK

    # split the host list in number of threads
    threadHostArray = array_split(processArray, this.threads)

    # init threading pool
    tPool = ThreadPool(this.threads)
    try:
        # start threading pool
        tPool.map_async(__threading, threadHostArray).get(9999999)
    except KeyboardInterrupt:
        PLOCK.aquire()
        if once.value == 0:
            once.value += 1
            print('\n\n[!] killing all python processes')
            # use pkill to make sure every thread is killed
            os.system('pkill python')
            sys.exit(0)
    # close threading pool
    tPool.close()
    tPool.join()


def __threading(threadArray):
    # init global vars
    global cur
    global curPercent
    global countServer
    global countOpen
    global once
    global PLOCK
    global TLOCK

    # magic
    for host in threadArray:
        # update counter variable
        cur.value += 1

        # convert object ip to string ip
        ip = str(host)

        try:
            # discover with ping
            if this.noping == 0:
                # send an icmp packet to check host state
                answer = sr1(IP(dst=ip) / ICMP(), timeout=this.timeout / 2, verbose=0)

                # check if icmp answer
                if answer != None:
                    countServer.value += 1
                    for dstPort in this.dstPorts:
                        # create socket
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        sock.settimeout(this.timeout)

                        try:
                            # discovering
                            if sock.connect_ex((ip, dstPort)) == 0:
                                # port open
                                # check brute ability
                                if this.brute == 1:
                                    if __checkBrute(ip, dstPort) == True:
                                        # count open ports
                                        countOpen.value += 1

                                        extraOUT = ''

                                        # discover hostname
                                        if this.hostname == 1:
                                            h = __discover(ip, dstPort, hostname=1)
                                            extraOUT += ' ' + h

                                        # discover os
                                        if this.osDiscovery == 1:
                                            o = __discover(ip, dstPort, osDiscovery=1)
                                            extraOUT += ' ' + o

                                        # discover service
                                        if this.service == 1:
                                            s = __discover(ip, dstPort, service=1)
                                            extraOUT += ' ' + s

                                        # save to file
                                        with open(this.outFileName, 'a') as outFile:
                                            outFile.write(ip + ':' + str(dstPort) + extraOUT + '\n')
                                if this.amp == 1:
                                    if __checkAmp(ip, dstPort) == True:
                                        # count open ports
                                        countOpen.value += 1

                                        extraOUT = ''

                                        # discover hostname
                                        if this.hostname == 1:
                                            h = __discover(ip, dstPort, hostname=1)
                                            extraOUT += ' ' + h

                                        # discover os
                                        if this.osDiscovery == 1:
                                            o = __discover(ip, dstPort, osDiscovery=1)
                                            extraOUT += ' ' + o

                                        # discover service
                                        if this.service == 1:
                                            s = __discover(ip, dstPort, service=1)
                                            extraOUT += ' ' + s

                                        # save to file
                                        with open('amp-' + this.outFileName, 'a') as outFile:
                                            outFile.write(ip + ':' + str(dstPort) + ' amp=' + str(
                                                this.factors[ip]) + extraOUT + '\n')
                                if this.brute == 0 and this.amp == 0:
                                    # count open ports
                                    countOpen.value += 1

                                    extraOUT = ''

                                    # discover hostname
                                    if this.hostname == 1:
                                        h = __discover(ip, dstPort, hostname=1)
                                        extraOUT += ' ' + h

                                    # discover os
                                    if this.osDiscovery == 1:
                                        o = __discover(ip, dstPort, osDiscovery=1)
                                        extraOUT += ' ' + o

                                    # discover service
                                    if this.service == 1:
                                        s = __discover(ip, dstPort, service=1)
                                        extraOUT += ' ' + s

                                    # save to file
                                    with open(this.outFileName, 'a') as outFile:
                                        outFile.write(ip + ':' + str(dstPort) + extraOUT + '\n')
                            else:
                                # port closed/filtered
                                pass
                        except Exception:
                            # host down
                            pass
                        finally:
                            # close socket
                            sock.close()
            else:
                # discover without ping
                for dstPort in this.dstPorts:
                    # create socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.settimeout(this.timeout)

                    try:
                        # discovering
                        if sock.connect_ex((ip, dstPort)) == 0:
                            # port open
                            countServer.value += 1
                            # check brute ability
                            if this.brute == 1:
                                if __checkBrute(ip, dstPort) == True:
                                    # count open ports
                                    countOpen.value += 1

                                    extraOUT = ''

                                    # discover hostname
                                    if this.hostname == 1:
                                        h = __discover(ip, dstPort, hostname=1)
                                        extraOUT += ' ' + h

                                    # discover os
                                    if this.osDiscovery == 1:
                                        o = __discover(ip, dstPort, osDiscovery=1)
                                        extraOUT += ' ' + o

                                    # discover service
                                    if this.service == 1:
                                        s = __discover(ip, dstPort, service=1)
                                        extraOUT += ' ' + s

                                    # save to file
                                    with open(this.outFileName, 'a') as outFile:
                                        outFile.write(ip + ':' + str(dstPort) + extraOUT + '\n')
                            if this.amp == 1:
                                if __checkAmp(ip, dstPort) == True:
                                    # count open ports
                                    countOpen.value += 1

                                    extraOUT = ''

                                    # discover hostname
                                    if this.hostname == 1:
                                        h = __discover(ip, dstPort, hostname=1)
                                        extraOUT += ' ' + h

                                    # discover os
                                    if this.osDiscovery == 1:
                                        o = __discover(ip, dstPort, osDiscovery=1)
                                        extraOUT += ' ' + o

                                    # discover service
                                    if this.service == 1:
                                        s = __discover(ip, dstPort, service=1)
                                        extraOUT += ' ' + s

                                    # save to file
                                    with open('amp-' + this.outFileName, 'a') as outFile:
                                        outFile.write(
                                            ip + ':' + str(dstPort) + ' amp=' + str(this.factors[ip]) + extraOUT + '\n')
                            if this.brute == 0 and this.amp == 0:
                                # count open ports
                                countOpen.value += 1

                                extraOUT = ''

                                # discover hostname
                                if this.hostname == 1:
                                    h = __discover(ip, dstPort, hostname=1)
                                    extraOUT += ' ' + h

                                # discover os
                                if this.osDiscovery == 1:
                                    o = __discover(ip, dstPort, osDiscovery=1)
                                    extraOUT += ' ' + o

                                # discover service
                                if this.service == 1:
                                    s = __discover(ip, dstPort, service=1)
                                    extraOUT += ' ' + s

                                # save to file
                                with open(this.outFileName, 'a') as outFile:
                                    outFile.write(ip + ':' + str(dstPort) + extraOUT + '\n')
                        else:
                            # port closed/filtered
                            pass
                    except Exception:
                        # host down
                        pass
                    finally:
                        # close socket
                        sock.close()

            # check verbose mode
            if this.verbose == 0:
                # print refresh body if something is changed
                if (cur.value % 256 == 0 and once.value == 0) or (
                        int((cur.value * 100) / len(this.ips)) > curPercent.value and once.value == 0):
                    # print only once at the same moment to prevent print bugs
                    once.value = 1
                    # lock stdout to prevent print lags
                    PLOCK.acquire()
                    TLOCK.acquire()
                    # print status
                    __printStatus()
                    # release the stdout lock
                    TLOCK.release()
                    PLOCK.release()


        except Exception as e:
            # debug
            print('[!] FAILED: ' + str(e))
            traceback.print_exc()


def __printStatus():
    # get percent of process
    curPercent.value = int((cur.value * 100) / len(this.ips))

    # define print values
    # ip range
    if type(this.ips) is list:
        writeIPS = 'File Input'
    else:
        writeIPS = str(this.ips.network) + '/' + str(int(32 - log(len(this.ips), 2)))
    # ports
    writePorts = ''
    curP = 0
    last = len(this.dstPorts)
    for port in this.dstPorts:
        curP += 1
        if curP == last:
            writePorts += str(port)
        else:
            writePorts += str(port) + ','
    # check print length
    if len(writePorts) > 20:
        writePorts = 'List of Ports'
    # pertcent
    writePercent = str(curPercent.value) + ' %  [' + str(cur.value) + ']'
    # server count
    writeOpen = str(countOpen.value) + '  [' + str(countServer.value) + ']'

    # define special terminal prints
    CURSOR_UP_ONE = '\x1b[1A'
    ERASE_LINE = '\x1b[2K'

    # erease current body and write the first line
    print(
        CURSOR_UP_ONE + CURSOR_UP_ONE + CURSOR_UP_ONE + ERASE_LINE + '  |                  |                    |                  |                  |  ')

    # parsing the second line
    sys.stdout.write('  ')
    sys.stdout.write('|')

    # center ip
    l = 18 - len(writeIPS)
    if len(writeIPS) % 2 == 0:
        spaces = int(l / 2)
        for i in range(0, spaces):
            sys.stdout.write(' ')
        sys.stdout.write(this.WARNING + writeIPS + this.OKCYAN)
        for i in range(0, spaces):
            sys.stdout.write(' ')
    else:
        spaces = int(l / 2)
        for i in range(0, spaces):
            sys.stdout.write(' ')
        sys.stdout.write(this.WARNING + writeIPS + this.OKCYAN)
        for i in range(spaces + 1):
            sys.stdout.write(' ')
    sys.stdout.write('|')

    # center ports
    l = 20 - len(writePorts)
    if len(writePorts) % 2 == 0:
        spaces = int(l / 2)
        for i in range(0, spaces):
            sys.stdout.write(' ')
        sys.stdout.write(this.WARNING + writePorts + this.OKCYAN)
        for i in range(0, spaces):
            sys.stdout.write(' ')
    else:
        spaces = int(l / 2)
        for i in range(0, spaces):
            sys.stdout.write(' ')
        sys.stdout.write(this.WARNING + writePorts + this.OKCYAN)
        for i in range(spaces + 1):
            sys.stdout.write(' ')
    sys.stdout.write('|')

    # center percent
    l = 18 - len(writePercent)
    if len(writePercent) % 2 == 0:
        spaces = int(l / 2)
        for i in range(0, spaces):
            sys.stdout.write(' ')
        sys.stdout.write(this.WARNING + writePercent + this.OKCYAN)
        for i in range(0, spaces):
            sys.stdout.write(' ')
    else:
        spaces = int(l / 2)
        for i in range(0, spaces):
            sys.stdout.write(' ')
        sys.stdout.write(this.WARNING + writePercent + this.OKCYAN)
        for i in range(spaces + 1):
            sys.stdout.write(' ')
    sys.stdout.write('|')

    # center server count
    l = 18 - len(writeOpen)
    if len(writeOpen) % 2 == 0:
        spaces = int(l / 2)
        for i in range(0, spaces):
            sys.stdout.write(' ')
        sys.stdout.write(this.WARNING + writeOpen + this.OKCYAN)
        for i in range(0, spaces):
            sys.stdout.write(' ')
    else:
        spaces = int(l / 2)
        for i in range(0, spaces):
            sys.stdout.write(' ')
        sys.stdout.write(this.WARNING + writeOpen + this.OKCYAN)
        for i in range(spaces + 1):
            sys.stdout.write(' ')

    sys.stdout.write('|')
    sys.stdout.write('  \n')

    # write last line
    print('  |__________________|____________________|__________________|__________________|  ')

    # reset print once variable
    once.value = 0


def __discover(ip, dstPort, hostname=0, osDiscovery=0, service=0):
    try:
        # discover hostname
        if hostname == 1:
            try:
                name = 'hostname=\'' + socket.gethostbyaddr(ip)[0] + '\''
                if name == '' or name == None:
                    name = 'hostname=\'unknown\''
            except:
                name = 'hostname=\'unknown\''
            return name

        # discover os
        if osDiscovery == 1:
            # init nmap scanner 'very slow
            n = nmap.PortScanner()
            # start scan for OS detection
            n.scan(hosts=ip, arguments='-p ' + str(dstPort) + '-' + str(dstPort + 5) + ',31337,42427 -T4 -O')
            # save the object information and return
            try:
                os = 'os=\'' + n[ip]['osmatch'][0]['name'] + '\''
            except:
                os = 'os=\'unknown\''
            return os

        # discover service
        if service == 1:
            try:
                # open socket for service detection
                servSock = socket.socket()
                servSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                servSock.settimeout(this.timeout)
                servSock.connect((ip, dstPort))
                # get service banner
                serv = servSock.recv(1024)
                servSock.close()
                # if we got a banner
                if serv != '':
                    serv = serv.replace('\n', '')
                    serv = serv.replace('\r', '')
                    serv = 'service=\'' + serv + '\''
                else:
                    # discover with socket dictionary
                    serv = 'service=\'' + socket.getservbyport(dstPort) + '\''
            except:
                # no banner not known
                serv = 'service=\'unknown\''
            return serv
    except KeyboardInterrupt:
        PLOCK.aquire()
        TLOCK.aquire()
        if once.value == 0:
            once.value += 1
            print('\n\n[!] killing all python processes')
            # use pkill to make sure every process is killed
            os.system('pkill python')
            sys.exit(0)


def __checkBrute(ip, port):
    # ssh
    if port == 22:
        # init ssh client
        ssh = paramiko.SSHClient()
        # auto accept policy
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(ip, port=22, username='root', password='toor', timeout=2)
            # no comment..
            print('\n  [OMG] ' + ip + ':' + str(port) + ':root:toor !\n\n\n\n')
            return True
        except paramiko.AuthenticationException:
            # authentication failed
            return True
        except paramiko.ssh_exception.SSHException:
            # wrong banner
            return False
        except socket.error as e:
            # connection closed
            return False
        else:
            return False
    else:
        return True


def __checkAmp(ip, port):
    # dns
    if port == 53:
        # send dns request
        answer = sr1(IP(dst=ip) / UDP(sport=randint(4000, 64000), dport=53) / DNS(rd=1, qd=DNSQR(qname='google.com',
                                                                                                 qtype='ALL')),
                     timeout=1, verbose=0)
        # if answer recieved
        if answer != None:
            # if we found an amp factor
            if len(answer) + 16 > 88:
                # amplification factror
                this.factors[ip] = (len(answer) + 16) / 88
                return True
            else:
                return False
        else:
            return False

    # store payloads for serveral services
    PAYLOAD = {
        'chargen': ('0'),
        'ntp': ('\x17\x00\x02\x2a' + '\x00' * 4),
        'snmp': ('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
                 '\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
                 '\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
                 '\x01\x02\x01\x05\x00'),
        'ssdp': ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
                 'MAN: \'ssdp:discover\'\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'),
        'quake': ('\xFF\xFF\xFF\xFF\x67\x65\x74\x73\x74\x61\x74\x75\x73\x10')
    }
    # store payload ports
    PORTS = {
        19: ('chargen'),
        123: ('ntp'),
        161: ('snmp'),
        1900: ('ssdp'),
        27960: ('quake')
    }

    # chargen,ntp,snmp,
    if port in PORTS:
        # set random soucre port
        srcPort = randint(4000, 64000)

        # start packet sniffer
        Thread(target=__sniff, args=(srcPort, 1.5,)).start()

        # init sleep
        sleep(0.1)

        # send ntp monlist command
        send(IP(dst=ip) / UDP(sport=srcPort, dport=port) / Raw(load=PAYLOAD[PORTS[port]]), verbose=0)

        # wait for answers and sniffer to finish
        sleep(1.5)

        # define send and recieve variables
        sndB = 0
        rcvB = 0
        lenList = []

        # if we got an answer
        if len(this.packets[srcPort]) > 1:
            # save the length of each packet to lenList variable
            p = 0
            while True:
                try:
                    lenList.append(len(this.packets[srcPort][p]))
                    p += 1
                except:
                    break
            p = 0

            # get the send packet
            lenListMin = min(lenList)

            # go through each packet and add the lenght to the variables
            while True:
                try:
                    if len(this.packets[srcPort][p]) > lenListMin:
                        rcvB += len(this.packets[srcPort][p])
                    elif len(this.packets[srcPort][p]) == lenListMin:
                        sndB += len(this.packets[srcPort][p])
                    p += 1
                except:
                    break

            # check for amplification
            if rcvB > sndB:
                # amplification factror
                this.factors[ip] = rcvB / sndB
                return True
            else:
                # no amplification
                return False
        else:
            # no answer
            return False

        # relese the dictionary key
        this.packets.pop(srcPort)
    else:
        # unknown protocol
        return False


def __sniff(srcPort, timeout):
    # starting sniffer on given port for given time
    this.packets[srcPort] = sniff(filter='udp and port ' + str(srcPort), timeout=timeout)


def __cleanFile(cleanFile):
    # get created file name
    # default 'servers.txt'
    cleanFileName = str(cleanFile)

    if this.amp == 0:
        try:
            # open previous created file
            cleanFileRead = open(cleanFileName, 'r')

            # set complete dictionary containing all ports and ips
            lines = {}

            # load ips to each dictionary port
            with cleanFileRead as rows:
                for line in rows:
                    line = line.replace('\n', '')
                    line = line.split(':')
                    line[0] += '\n'

                    # check ifkey port exists
                    if line[1] in lines:
                        lines[line[1]].append(line[0])
                    else:
                        lines[line[1]] = []
                        lines[line[1]].append(line[0])

            # close previous created file
            cleanFileRead.close()

            # load preavious scans if exists for each port
            for port in this.dstPorts:
                try:
                    with open(str(port) + '.txt', 'r') as rows:
                        for line in rows:
                            # append previous to current
                            lines[str(port)].append(line)
                except:
                    # create new file
                    pass

                # write to new file
                # remove duplicates
                lines[str(port)] = list(set(lines[str(port)]))
                # open new file
                cleanFile = open(str(port) + '.txt', 'w')
                # write lines
                for line in lines[str(port)]:
                    cleanFile.write(line)
                # close new file
                cleanFile.close()
        except:
            pass
    else:
        # amp = 1

        # define ipDictionary
        ipDict = {}

        try:
            # read from file and skip duplicates
            with open(cleanFileName, 'r') as lines:
                for line in lines:
                    line = line.split(':')
                    ipDict[line[0]] = line[1]

            # write clean data to file
            cleanFile = open(cleanFileName, 'w')

            # write lines
            for ip in ipDict:
                cleanFile.write(ip + ':' + ipDict[ip])

            # close new file
            cleanFile.close()
        except:
            pass


def __printHelp(parser, string):
    sys.stdout.write('\x1b[8;33;83t')
    print(str(string) + '\n')
    parser.print_help()
    sys.exit(0)


def init():
    # make some beauty
    sys.stdout.write(this.OKCYAN)

    # write examples in epilog
    epilog = '# powerscan -i 10.10.10.0/24 -p 21,22,53,123                                    '
    epilog += '# powerscan -i 10.10.0.0/16 -p 22 --threads=16 --processes=4 --hostname        '
    epilog += '# powerscan -l hosts.txt -p 22 --noping --service --brute --verbose            '

    # parse args
    parser = OptionParser('usage: # powerscan [required] [optional]', epilog=epilog)

    # define groups
    required = OptionGroup(parser, 'Required')
    optional = OptionGroup(parser, 'Optional')
    examples = OptionGroup(parser, 'Examples')

    # define options
    parser.add_option('-v', '--version', action='store_true',
                      help='display the the version of powerscan',
                      dest='version')

    required.add_option('-i', type='string', metavar='range',
                        help='set IP range [10.0.0.0/24]',
                        dest='ipRange')

    required.add_option('-l', type='string', metavar='file',
                        help='load IPs from file [1 IP/line]',
                        dest='fileInput')

    required.add_option('-p', type='string', metavar='ports',
                        help='specify ports seperated by \',\' or \'-\' for range',
                        dest='ports')

    optional.add_option('--threads', metavar='1-64',
                        help='number of threads',
                        dest='threads')

    optional.add_option('--processes', metavar='1-32',
                        help='number of processes [default=cpu_count]',
                        dest='processes')

    optional.add_option('--timeout', metavar='2',
                        help='set timeout [1-5]',
                        dest='timeout')

    optional.add_option('--noping', action='store_true',
                        help='do not ping targets',
                        dest='noping')

    optional.add_option('--hostname', action='store_true',
                        help='discover hostnames for open servers',
                        dest='hostname')

    optional.add_option('--os', action='store_true',
                        help='discover os for open servers [slow]',
                        dest='os')

    optional.add_option('--service', action='store_true',
                        help='discover services for open ports',
                        dest='service')

    optional.add_option('--brute', action='store_true',
                        help='only save servers that are vuln againt brute-forcing',
                        dest='brute')

    optional.add_option('--amp', action='store_true',
                        help='only save servers with amplification factor',
                        dest='amp')

    optional.add_option('--verbose', action='store_true',
                        help='run in verbose mode',
                        dest='verbose')

    optional.add_option('--out', metavar='file',
                        help='set output file',
                        dest='out')

    # add groups to parser
    parser.add_option_group(required)
    parser.add_option_group(optional)
    parser.add_option_group(examples)

    # parse options
    (options, args) = parser.parse_args()

    # display help if no given argument
    if len(sys.argv[1:]) == 0:
        __printHelp(parser, '[!] please give me an argument')
    else:
        # check root privileges
        c = 0
        try:
            if os.geteuid() != 0:
                p = '[sudo] password for %u:'
                c = subprocess.check_call('sudo -v -p \'%s\'' % p, shell=True)
            if c != 0:
                __printHelp(parser, '[!] unauthorized operation')
        except KeyboardInterrupt:
            sys.exit(0)

        # display verion if needed
        if options.version:
            print("\n   [*][*][*][*][*][*][*][*][*][*][*][*]")
            print("   |||                              |||")
            print("   |||   PowerScan                  |||")
            print("   |||   Author: vP3nguin           |||")
            print("   |||   Version: 0.1               |||")
            print("   |||   Date: May 2021             |||")
            print("   |||                              |||")
            print("   [*][*][*][*][*][*][*][*][*][*][*][*]\n")
            sys.exit(0)

        # test network connection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('10.255.255.255', 0))
            IP = s.getsockname()[0]
            this.ip = str(IP)
            s.close()
        except:
            __printHelp(parser, '[!] check your network connection')

        # check if verbose mode is set to improve speed
        if options.verbose:
            this.verbose = 1
        else:
            this.verbose = 0

    if this.verbose == 0:
        # print head output
        print('\x1b[8;21;83t' + this.ENDC + this.FAIL)
        os.system('clear')
        print(' ' + this.BOLD)
        print('                               PowerScan - Version 0.1                   ')
        print(' ' + this.ENDC + this.OKCYAN)
        print('   _____________________________________________________________________________   ')
        print('  |                  |                    |                  |                  |  ')
        print(
            '  |     ' + this.BOLD + 'IP Range' + this.ENDC + this.OKCYAN + '     |       ' + this.BOLD + 'Ports' + this.ENDC + this.OKCYAN + '        |     ' + this.BOLD + 'Progress' + this.ENDC + this.OKCYAN + '     |   ' + this.BOLD + 'Open Servers' + this.ENDC + this.OKCYAN + '   |  ')
        print('  |-----------------------------------------------------------------------------|  ')
        print('  |                                                                             |  ')
        print(
            '  |                              ' + this.BOLD + this.OKGREEN + '... Loading ...' + this.ENDC + this.OKCYAN + '                                |  ')
        print('  |_____________________________________________________________________________|  ')

    if options.ipRange or options.fileInput:

        # subnet input
        if options.ipRange:
            try:
                # write ips from subnet into a list
                hosts = getAddrList(options.ipRange)
                this.ips = hosts
            except:
                __printHelp(parser, '[!] invalid IP range')

        # file input
        if options.fileInput:
            try:
                # write ips from file into a list
                hosts = []
                with open(str(options.fileInput), 'r') as inputFile:
                    for line in inputFile:
                        line = line.replace('\n', '')
                        hosts.append(line)
                this.ips = hosts
            except:
                __printHelp(parser, '[!] cannot load file')

        # define a list of scanning ports
        this.dstPorts = []
        try:
            if options.ports:
                portList = options.ports.split(',')
                for port in portList:
                    # if port range given
                    if '-' in port:
                        p = port.split('-')
                        for p in range(int(p[0]), int(p[1]) + 1):
                            this.dstPorts.append(int(p))
                    else:
                        this.dstPorts.append(int(port))
        except:
            __printHelp(parser, '[!] invalid port number')

        # set thread number
        if options.threads:
            try:
                if int(options.threads) > 0:
                    this.threads = int(options.threads)
                else:
                    __printHelp(parser, '[!] invalid thread number')
            except:
                __printHelp(parser, '[!] invalid thread number')
        else:
            this.threads = 10

        # set process number
        if options.processes:
            try:
                if int(options.processes) > 0:
                    processes = int(options.processes)
                else:
                    __printHelp(parser, '[!] invalid process number')
            except:
                __printHelp(parser, '[!] invalid process number')
        else:
            processes = cpu_count()

        # set and test output file [default is servers.txt]
        if options.out:
            try:
                this.outFileName = str(options.out)
                testFile = open(this.outFileName, 'a')
                testFile.close()
            except:
                __printHelp(parser, '[!] invalid filename')
        else:
            this.outFileName = 'servers.txt'

        # number of seconds to wait for icmp response
        # the timeout of port discoviring is as twice as much!
        if options.timeout:
            try:
                this.timeout = float(options.timeout)
            except:
                __printHelp(parser, '[!] invalid timeout number')
        else:
            this.timeout = 2

        # check if noping mode is set to scan host with disabled icmp
        if options.noping:
            this.noping = 1
        else:
            this.noping = 0

        # discover hostnames
        if options.hostname:
            this.hostname = 1
        else:
            this.hostname = 0

        # discover os
        if options.os:
            this.osDiscovery = 1
        else:
            this.osDiscovery = 0

        # discover services
        if options.service:
            this.service = 1
        else:
            this.service = 0

        # check if brute mode is set to run additional tests
        if options.brute:
            this.brute = 1
        else:
            this.brute = 0

        # check if amp mode is set to run additional tests
        if options.amp:
            this.amp = 1
        else:
            this.amp = 0

        # start scan
        __start(hosts, processes)
    else:
        # no ip rangean'
        __printHelp(parser, '[!] no ips to scan')


if __name__ == '__main__':
    init()
