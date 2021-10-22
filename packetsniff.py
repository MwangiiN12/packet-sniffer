
import socket, sys
from struct import *
from typing import Counter
from datetime import datetime
import time


#create a socket
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error as msg:
	print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
	sys.exit()

parsed_packets = []
parsed_packets_hour = {}
# set time to run
timeout = time.time() + 60*5
# listen for packets
while True:
	if time.time() > timeout:
		break
	current_hour = datetime.now().hour
	packet = s.recvfrom(65565)
	
	#packet string from tuple
	packet = packet[0]
	
	# get first 20 characters of ip header
	ip_header = packet[0:20]
	
	#unpack IP header
	iph = unpack('!BBHHHBBH4s4s' , ip_header)
	
	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF
	
	iph_length = ihl * 4
	

	source_addr = socket.inet_ntoa(iph[8])
	destination_addr = socket.inet_ntoa(iph[9])


		
	tcp_header = packet[iph_length:iph_length+20]
	
	#unpacking tcp header
	tcp_h = unpack('!HHLLBBHHH' , tcp_header)
	
	source_port = tcp_h[0]
	destination_port = tcp_h[1]
	unique_packet_key = '-'.join([source_addr, destination_addr, str(source_port)])
	parsed_packets.append(unique_packet_key)
	parsed_packets_hour[unique_packet_key] = current_hour

unique_counter = Counter(parsed_packets)
total_packet_count = len(parsed_packets)
unique_packets_count = len(unique_counter)


print(f'Total Packets Captured:   {total_packet_count}')
print('\n\n')
print('IP Observations')
print(f'Unique Combinations:      {unique_packets_count}')
print()
print(' ' * 47, '|', '-' * 40, 'Hourly Observations', '-' * 53, '|')
print()
print('Server', ' '*10, 'Client', ' '*6, 'Port', ' '*3, 'Type', ' '*2,
 '00  ', '01  ', '02  ', '03  ', '04  ', '05  ', '06  ', '07  ', '08  ',
  '09  ', '10  ', '11  ', '12  ', '13  ', '14  ', '15  ', '16  ', '17  ',
   '18  ', '19  ', '20  ', '21  ', '22  ', '23  ')

for packet_info in unique_counter:
	info_list = packet_info.split('-')
	hour = parsed_packets_hour[packet_info]
	server, client, port = info_list
	print(f'{server}', ' '*2, client, ' '*2, port, ' '*2, 'TCP', ' '*4, '0    ' * (int(hour)-1), '0  ', f'{unique_counter[packet_info]}  ', '0    ' * int(23-int(hour)))
	
