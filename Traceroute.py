# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select

# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 5
        __ttl = 0                       # Time to live
        __rtt = 0                       # rtt of packet when sent over network

        __DEBUG_IcmpPacket = False      # Allows for debug output


        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):

            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        def getRtt(self):
            return self.__rtt

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setRtt(self, rtt):
            self.__rtt = rtt

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # TODO __validateIcmpReplyPacketWithOriginalPingData

            # Check validity of received data
            sameSeqNum = self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber()
            samePacketIdentifier = self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier()
            sameRawData = self.getDataRaw() == icmpReplyPacket.getIcmpData()

            # Set corresponding variables of icmpReplyPacket
            icmpReplyPacket.setIcmpSequenceNumber_isValid(sameSeqNum)
            icmpReplyPacket.setIcmpIdentifier_isValid(samePacketIdentifier)
            icmpReplyPacket.setIcmpRawData_isValid(sameRawData)

            # Set response validity based on received data
            if sameSeqNum and samePacketIdentifier and sameRawData:
                icmpReplyPacket.setIsValidResponse(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self, traceroute):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    # Dictionary lookup for icmp errors
                    # Errors determined from below source
                    # https://canvas.oregonstate.edu/courses/1967031/pages/exploration-the-internet-control-message-protocol-icmp-2?module_item_id=24526094
                    icmpError = {
                        '0': {'0': "echo reply"},
                        '3': {
                            '0': "Destination network unreachable",
                            '1': "Destination host unreachable",
                            '2': "Destination protocol unreachable",
                            '3': "Destination port unreachable",
                            '6': "Destination network unknown",
                            '7': "Destination host unknown"
                        },
                        '4': {'0': "source quench"},
                        '8': {'0': "echo request"},
                        '9': {'0': "route advertisement"},
                        '10': {'0': "router solicitation"},
                        "11": {"0": "TTL expired"},
                        '12': {'0': "bad IP header"}
                    }

                    # If icmp packet did not reach specified host
                    if icmpType != 0:                          # Time Exceeded
                        print("    TTL=%d    RTT=%.0f ms    Type=%d   Code=%d %s    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    icmpError[str(icmpType)][str(icmpCode)],
                                    addr[0]
                                )
                              )

                    # If icmp packet reached specified host
                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)

                        # Set ttl based on received packet, account for OS default ttl set from host
                        # Default ttl settings determined from below source
                        # https://www.imperva.com/learn/performance/time-to-live-ttl/
                        if not traceroute:
                            # Position of ttl in reply determined from below source
                            # https://datatracker.ietf.org/doc/html/rfc791#section-3.1
                            receivedTtl = recvPacket[8]
                            if receivedTtl < 64:
                                self.setTtl(64 - receivedTtl)
                            elif receivedTtl <= 128:
                                self.setTtl(128 - receivedTtl)
                            else:
                                self.setTtl(255 - receivedTtl)

                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, self)
                        return True

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()


        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        __IcmpIdentifier_isValid = False
        __IcmpSequenceNumber_isValid = False
        __IcmpRawData_isValid = False


        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def getIcmpIdentifier_isValid(self):
            return self.__IcmpIdentifier_isValid

        def getIcmpSequenceNumber_isValid(self):
            return self.__IcmpSequenceNumber_isValid

        def getIcmpRawData_isValid(self):
            return self.__IcmpRawData_isValid

        def isValidResponse(self):
            return self.__isValidResponse

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.__IcmpIdentifier_isValid = booleanValue

        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.__IcmpSequenceNumber_isValid = booleanValue

        def setIcmpRawData_isValid(self, booleanValue):
            self.__IcmpRawData_isValid = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr, req_packet):
            debug = False
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]

            # Debug prints
            if debug:
                print("---SENT VS RECEIVED COMPARISONS---")
                print(f"SENT seqNum: {req_packet.getPacketSequenceNumber()}    RECEIVED seqNum: {self.getIcmpSequenceNumber()}")
                print(f"SENT Packet Identifier: {req_packet.getPacketIdentifier()}    RECEIVED Packet Identifier: {self.getIcmpIdentifier()}")
                print(f"SENT Raw Data: {req_packet.getDataRaw()}    RECEIVED Raw Data: {self.getIcmpData()}")

            # Print data anomalies
            if not self.isValidResponse():
                if self.getIcmpSequenceNumber() != req_packet.getPacketSequenceNumber():
                    print(f"Incorrect sequence number. Expected {req_packet.getPacketSequenceNumber()}, received {self.getIcmpSequenceNumber()}")

                if self.getIcmpIdentifier() != req_packet.getPacketIdentifier():
                    print(f"Incorrect Identifier. Expected {req_packet.getPacketIdentifier()}, received {self.getIcmpIdentifier()}")

                if self.getIcmpData() != req_packet.getDataRaw():
                    print(f"Incorrect sequence number. Expected {req_packet.getDataRaw()}, received {self.getIcmpData()}")

            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d echo reply       Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )

            # Set rtt of sent packet after receiving from host
            req_packet.setRtt((timeReceived - timeSent) * 1000)
            print()

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output
    rttsList = []                                          # Build list of RTTs when sending Pings
    droppedPacketsList = []                                # Track any dropped packets when sending Pings
    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    def __sendIcmpEchoRequest(self, host, traceroute=False, iterations=1):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # Build packet
        icmpPacket = IcmpHelperLibrary.IcmpPacket()

        # set ttl based on traceroute or ping iteration
        if traceroute:
            icmpPacket.setTtl(iterations)
        else:
            icmpPacket.setTtl(50)

        randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                       # Some PIDs are larger than 16 bit

        packetIdentifier = randomIdentifier
        packetSequenceNumber = iterations - 1

        icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
        icmpPacket.setIcmpTarget(host)

        # If icmpPacket reaches specified host
        if icmpPacket.sendEchoRequest(traceroute):

            # If traceroute, return
            if traceroute:
                return True

            # Else track rtt
            else:
                self.setDroppedPacketsList(False)
                self.setRttsList(icmpPacket.getRtt())

        # Else track dropped packet
        elif not traceroute:
            self.setDroppedPacketsList(True)

        icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
        icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
        # we should be confirming values are correct, such as identifier and sequence number and data

    def __sendIcmpTraceRoute(self, host):
        # TODO _sendIcmpTraceRoute
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # Send ICMP packets in specified range to build traceroute to host
        for ICMP in range(1, 51):
            if self.sendPing(host, True, ICMP):
                break
            if ICMP == 50:
                print("Max hops reached")
                break

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost, traceroute=False, iterations=10):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        try:
            # If only sending a Ping, not a traceroute
            if not traceroute:

                # Send specified amount of Pings
                for ping in range(1, iterations + 1):
                    self.__sendIcmpEchoRequest(targetHost, traceroute, ping)

                # Set up data for rtts
                if len(self.rttsList) > 0:
                    minRtt = round(min(self.rttsList))
                    maxRtt = round(max(self.rttsList))
                    avgRtt = round(sum(self.rttsList) / len(self.rttsList), 2)
                else:
                    minRtt = "N/A"
                    maxRtt = "N/A"
                    avgRtt = "N/A"

                # Set up data for dropped packets
                droppedNum = 0
                for packet in self.droppedPacketsList:
                    if packet == True:
                        droppedNum += 1
                droppedPercent = (droppedNum / len(self.droppedPacketsList)) * 100

                # Print min/max/average/packet loss data
                print(f"Min: {minRtt}, Max: {maxRtt}, Average: {avgRtt}, Packet Loss Rate: {droppedPercent}%\n")

            else: # Send Ping with traceroute flag enabled
                return self.__sendIcmpEchoRequest(targetHost, traceroute, iterations)
        except:
            print("Please enter valid arguments")

    def getRttsList(self):
        return self.rttsList

    def getDroppedPacketsList(self):
        return self.droppedPacketsList

    def setRttsList(self, rtt):
        self.rttsList.append(rtt)

    def setDroppedPacketsList(self, droppedPacket):
        self.droppedPacketsList.append(droppedPacket)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)

# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("122.56.99.243")
    # icmpHelperPing.sendPing("200.10.227.250")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")

    # gets type 3 errors
    # icmpHelperPing.sendPing("200.10.227.250")

    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("www.india.gov.in")
    # icmpHelperPing.sendPing("www.dfat.gov.au")
    # icmpHelperPing.sendPing("www.norway.no")

    # North America
    icmpHelperPing.traceRoute("www.google.com")

    # India
    icmpHelperPing.traceRoute("www.india.gov.in")

    # Australia
    icmpHelperPing.traceRoute("www.dfat.gov.au")

    # Norway
    icmpHelperPing.traceRoute("www.norway.no")

if __name__ == "__main__":
    main()
