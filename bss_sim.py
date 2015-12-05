#!/usr/bin/python

import sys
import socket
import logging 
import binascii

# CRC code inspired by vGSN (UnifyCore)

CRC24_TABLE = (
	0x00000000, 0x00d6a776, 0x00f64557, 0x0020e221, 0x00b78115, 0x00612663, 0x0041c442, 0x00976334,
        0x00340991, 0x00e2aee7, 0x00c24cc6, 0x0014ebb0, 0x00838884, 0x00552ff2, 0x0075cdd3, 0x00a36aa5,
        0x00681322, 0x00beb454, 0x009e5675, 0x0048f103, 0x00df9237, 0x00093541, 0x0029d760, 0x00ff7016,
        0x005c1ab3, 0x008abdc5, 0x00aa5fe4, 0x007cf892, 0x00eb9ba6, 0x003d3cd0, 0x001ddef1, 0x00cb7987,
        0x00d02644, 0x00068132, 0x00266313, 0x00f0c465, 0x0067a751, 0x00b10027, 0x0091e206, 0x00474570,
        0x00e42fd5, 0x003288a3, 0x00126a82, 0x00c4cdf4, 0x0053aec0, 0x008509b6, 0x00a5eb97, 0x00734ce1,
        0x00b83566, 0x006e9210, 0x004e7031, 0x0098d747, 0x000fb473, 0x00d91305, 0x00f9f124, 0x002f5652,
        0x008c3cf7, 0x005a9b81, 0x007a79a0, 0x00acded6, 0x003bbde2, 0x00ed1a94, 0x00cdf8b5, 0x001b5fc3,
        0x00fb4733, 0x002de045, 0x000d0264, 0x00dba512, 0x004cc626, 0x009a6150, 0x00ba8371, 0x006c2407,
        0x00cf4ea2, 0x0019e9d4, 0x00390bf5, 0x00efac83, 0x0078cfb7, 0x00ae68c1, 0x008e8ae0, 0x00582d96,
        0x00935411, 0x0045f367, 0x00651146, 0x00b3b630, 0x0024d504, 0x00f27272, 0x00d29053, 0x00043725,
        0x00a75d80, 0x0071faf6, 0x005118d7, 0x0087bfa1, 0x0010dc95, 0x00c67be3, 0x00e699c2, 0x00303eb4,
        0x002b6177, 0x00fdc601, 0x00dd2420, 0x000b8356, 0x009ce062, 0x004a4714, 0x006aa535, 0x00bc0243,
        0x001f68e6, 0x00c9cf90, 0x00e92db1, 0x003f8ac7, 0x00a8e9f3, 0x007e4e85, 0x005eaca4, 0x00880bd2,
        0x00437255, 0x0095d523, 0x00b53702, 0x00639074, 0x00f4f340, 0x00225436, 0x0002b617, 0x00d41161,
        0x00777bc4, 0x00a1dcb2, 0x00813e93, 0x005799e5, 0x00c0fad1, 0x00165da7, 0x0036bf86, 0x00e018f0,
        0x00ad85dd, 0x007b22ab, 0x005bc08a, 0x008d67fc, 0x001a04c8, 0x00cca3be, 0x00ec419f, 0x003ae6e9,
        0x00998c4c, 0x004f2b3a, 0x006fc91b, 0x00b96e6d, 0x002e0d59, 0x00f8aa2f, 0x00d8480e, 0x000eef78,
        0x00c596ff, 0x00133189, 0x0033d3a8, 0x00e574de, 0x007217ea, 0x00a4b09c, 0x008452bd, 0x0052f5cb,
        0x00f19f6e, 0x00273818, 0x0007da39, 0x00d17d4f, 0x00461e7b, 0x0090b90d, 0x00b05b2c, 0x0066fc5a,
        0x007da399, 0x00ab04ef, 0x008be6ce, 0x005d41b8, 0x00ca228c, 0x001c85fa, 0x003c67db, 0x00eac0ad,
        0x0049aa08, 0x009f0d7e, 0x00bfef5f, 0x00694829, 0x00fe2b1d, 0x00288c6b, 0x00086e4a, 0x00dec93c,
        0x0015b0bb, 0x00c317cd, 0x00e3f5ec, 0x0035529a, 0x00a231ae, 0x007496d8, 0x005474f9, 0x0082d38f,
        0x0021b92a, 0x00f71e5c, 0x00d7fc7d, 0x00015b0b, 0x0096383f, 0x00409f49, 0x00607d68, 0x00b6da1e,
        0x0056c2ee, 0x00806598, 0x00a087b9, 0x007620cf, 0x00e143fb, 0x0037e48d, 0x001706ac, 0x00c1a1da,
        0x0062cb7f, 0x00b46c09, 0x00948e28, 0x0042295e, 0x00d54a6a, 0x0003ed1c, 0x00230f3d, 0x00f5a84b,
        0x003ed1cc, 0x00e876ba, 0x00c8949b, 0x001e33ed, 0x008950d9, 0x005ff7af, 0x007f158e, 0x00a9b2f8,
        0x000ad85d, 0x00dc7f2b, 0x00fc9d0a, 0x002a3a7c, 0x00bd5948, 0x006bfe3e, 0x004b1c1f, 0x009dbb69,
        0x0086e4aa, 0x005043dc, 0x0070a1fd, 0x00a6068b, 0x003165bf, 0x00e7c2c9, 0x00c720e8, 0x0011879e,
        0x00b2ed3b, 0x00644a4d, 0x0044a86c, 0x00920f1a, 0x00056c2e, 0x00d3cb58, 0x00f32979, 0x00258e0f,
        0x00eef788, 0x003850fe, 0x0018b2df, 0x00ce15a9, 0x0059769d, 0x008fd1eb, 0x00af33ca, 0x007994bc,
        0x00dafe19, 0x000c596f, 0x002cbb4e, 0x00fa1c38, 0x006d7f0c, 0x00bbd87a, 0x009b3a5b, 0x004d9d2d
)

# computes LLC 24bit checksum 
def crc24(data):
	INIT = 0xFFFFFF
	crc = INIT
	for octet in data:
       		crc = (crc >> 8) ^ CRC24_TABLE[(crc ^ octet) & 0xff]
	crc = ~crc
	crc = crc & 0xffffff
	hex_crc = hex(crc)
	res = hex_crc[6:] + hex_crc[4:6] + hex_crc[2:4]
	return res 

############################
# IP and port configuration

peer_IP = "192.168.27.2"
local_port = 22000
remote_port = 23000
new_ptmsi = ''
attach_type = ''
###########################
# Gb protocols' states

NS_BLOCKED = 1
NS_UNBLOCKED = 0

###########################
logging.basicConfig(filename='/tmp/bss_sim.log', level=logging.DEBUG);

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
logging.info('Socket created')

#bind the socket to predefined port
s.bind(("", local_port))
logging.info('Ready to receive')

#receive


#send initial message - NS_RESET	
msg = "020081010182006504820065000000000000" 
byte_msg = msg.decode('hex')
s.sendto(byte_msg, (peer_IP, remote_port))

while 1:
	data, addr = s.recvfrom(2048)	
	hex_bytes =  binascii.hexlify(data)
	print hex_bytes	
	
	#if we receive a NS_ALIVE message, we reply with NS_ALIVE_ACK
	if data[0] == '\x0a':
		s.sendto('\x0b', (peer_IP, remote_port))	
		logging.info('Received NS_ALIVE packet from vGSN: %s' % hex_bytes)
	
	#if we receive a NS_RESET_ACK message and are in NS_BLOCKED state, we send a NS_UNBLOCK message
	elif data[0] == '\x03' and NS_BLOCKED:
		s.sendto('\x06', (peer_IP, remote_port))
		logging.info('Received NS_RESET_ACK packet from vGSN: %s' % hex_bytes)

	#if we receive a NS_UNBLOCK_ACK, we move to unblocked state and send a BVC_RESET
	elif data[0] == '\x07':
		logging.info('Received NS_UNBLOCK_ACK packet from vGSN: %s' % hex_bytes)
		NS_BLOCKED = 0
		NS_UNBLOCKED = 1 
		msg = "000000002204820000078108088809f1070001000000" 
		hex_msg = msg.decode('hex')	
		s.sendto(hex_msg, (peer_IP, remote_port))
	
	#if we reset BVCI 0, we need to reset BVCI 2
	elif data[0] == '\x00' and data[4] == '\x23':
		logging.info('Received BVC_RESET_ACK packet from vGSN: %s' % hex_bytes)
		
		#we reset BVCI 0, time to reset BVCI 2                
		if data[7] == '\x00' and data[8] == '\x00' :
			msg = "000000002204820002078108088809f1070001000000"
                	hex_msg = msg.decode('hex')
                	s.sendto(hex_msg, (peer_IP, remote_port))
		
		#if we reset BVCI 2, time to unblock BSSGP BVCI 2
		if data[7] == '\x00' and data[8] == '\x02':
 			msg = "000000002404820002"
			hex_msg = msg.decode('hex')
			s.sendto(hex_msg, (peer_IP, remote_port))
	
	#if we receive a UNBLOCK-ACK message, we might begin with FLOW_CONTROL, but...we are ready for ATTACH!!!
	elif data[0] == '\x00' and data[4] == '\x25':
		logging.info('Received BSSGP UNBLOCK_ACK packet from vGSN: %s' % hex_bytes)
		logging.info('sending ATTACH REQUEST')
		#attach with old P-TSMI	
		#msg = "00000002019428c68b000004088809f107000100000000800e002e01c001080102e5e001070405f4d428c68b32f110000a001119134233572bf7c84802134850c84802001716f0f403"
		#attach with IMSI
		attach_type = 'imsi'
		msg = "00000002019428c68b000004088809f107000100000000800e003101c001080102e5e001070408291310443582351132f110000a001119134233572bf7c84802134850c84802001716"
		hex_msg = msg.decode('hex')
		llc_crc = crc24(bytearray(msg[54:].decode('hex')))
		hex_msg += llc_crc.decode('hex')
		s.sendto(hex_msg, (peer_IP, remote_port))
	
	#if we attach with an unknown P-TMSI and receive an Identity Request, we respond with an Identity Response
	elif data[0] == '\x00'  and len(data) > 46 and data[45] == '\x15':
		logging.info('Received GMM Identity Request packet from vGSN: %s' % hex_bytes)
		
		if attach_type == 'imsi':
			print 'nay'

		if attach_type == 'ptmsi':
		
			#if IMEI is requested
			if data[46] == '\x02':	
				logging.info('Sending Identity Response with IMEI')
				msg = "00000002019428c68b000004088809f107000100000000800e001101c0050816083a85030013404403742073"
				hex_msg = msg.decode('hex')
				s.sendto(hex_msg, (peer_IP, remote_port))
	
			#if IMSI is requested
			if data[46] == '\x01':
				logging.info('Sending Identity Response with IMSI')
				msg = "00000002019428c68b000004088809f107000100000000800e001101c00908160829131044358235116a4ec7"
				hex_msg = msg.decode('hex')
				s.sendto(hex_msg, (peer_IP, remote_port))

	#if we receive an Identity request after an IMSI attach
	elif data[0] == '\x00' and len(data) > 55 and data[55] == '\x15':
		
		#if IMEI is requested
		if data[56] == '\x02':
			logging.info('Sending Identity Response with IMEI')
                        msg = "00000002019428c68b000004088809f107000100000000800e001101c0050816083a85030013404403"
			hex_msg = msg.decode('hex')
                        llc_crc = crc24(bytearray(msg[54:].decode('hex')))
			hex_msg += llc_crc.decode('hex')
			s.sendto(hex_msg, (peer_IP, remote_port))
	#if we receive an Attach Accept, we respond with an Attach Complete message
	elif data[0] == '\x00' and len(data) > 72 and data[55] == '\x02':
		logging.info('Received GMM Attach Accept packet from vGSN: %s' % hex_bytes)
		
		#new P-TMSI will be used as a new TLLI 
		new_ptmsi = data[68:72]	
		logging.info('Sending Attach Complete')
		msg = "0000000201" 
		msg += binascii.hexlify(new_ptmsi)
		msg += "000004088809f107000100000000800e000801c00d0803"
		llc_crc = crc24(bytearray(msg[54:].decode('hex')))
		hex_msg = msg.decode('hex')
		hex_msg += llc_crc.decode('hex')
		s.sendto(hex_msg, (peer_IP, remote_port))
		
		#when we are attached, we can activate a PDP context :)	
		msg = "0000000201"
		msg += binascii.hexlify(new_ptmsi)
		msg += "000004088809f107000100000000800e0044"
		llc_header = "01c0110a4105030c00001f000000000000000000020121280908696e7465726e6574271d80c0230601000006000080211001000010810600000000830600000000"		
		msg += llc_header
		llc_crc = crc24(bytearray(llc_header.decode('hex')))
		hex_msg = msg.decode('hex')
		hex_msg += llc_crc.decode('hex')
		s.sendto(hex_msg, (peer_IP, remote_port))

	else:
		logging.info('Message not implemented: %s' % hex_bytes)

# aby sme sa zbavili tychto hlupych zavislosti, napiseme si funkcie posielajuce jednotlive spravy,
# spravime bootstrap GPRS_NS a BSSGP a zvysne procedury budeme iniciovat rucne prikazmi z CLI
# ktore bude obsluhovat samostatny thread...pre procedury sa vytvoria automaty podobne ako teraz
# a stale vyvolame postupnost sprav podla nasich potrieb, treba uz len odsniffovat mozne scenare
