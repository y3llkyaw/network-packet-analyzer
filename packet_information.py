""""
This the course work module each function is one question
"""
import socket
import datetime
import sys
import re
import os
import dpkt
from tabulate import tabulate


def prase_packets(pcap_file):
    '''
        Prasing the packets from .pcap file to python data type
    '''
    # creating folder for the output files
    if not os.path.exists('output'):
        os.mkdir('output')
    # getting error_log.txt from sys.stderr
    with open('output/error_log.txt', 'w', encoding='utf-8') as sys.stderr:
        print(f"[#] Prasing the packets from {pcap_file}", file=sys.stderr)
        try:
            with open(pcap_file, "rb") as file:
                pcap = dpkt.pcap.Reader(file)
                packets = []
                for (time_stamp, buff) in pcap:
                    packets.append((time_stamp, buff))
                return packets
        except FileNotFoundError:
            print('\t', "[!] file does not exist", file=sys.stderr)
            return False


def dt_from_ts(time_stamp):
    '''
        not for a coursework just try not to do repeatly
    '''
    return datetime.datetime.utcfromtimestamp(time_stamp)


def is_other(packet):
    '''
        Checking whether not TCP or UDP or IGMP
    '''
    try:
        if not isinstance(packet, dpkt.igmp.IGMP):
            if not isinstance(packet, dpkt.udp.UDP):
                if not isinstance(packet.data, dpkt.tcp.TCP):
                    return True
        else:
            return False
    except TypeError:
        print('[!] Need to input one ip.data as arugment')


def show_summerize_table(packets):
    """
        showing summerize table for TCP,UDP,IGMP and others
    """
    with open('output/error_log.txt', 'a', encoding='utf-8') as sys.stderr:
        print('[#] Trying to show the summerize table', file=sys.stderr)
        # creating constant variables for packet type
        no_total = 0
        total_buff = 0
        packet_type = {
            'igmp': dpkt.igmp.IGMP,
            'tcp': dpkt.tcp.TCP,
            'udp': dpkt.udp.UDP}
        packet_info = {
            'tcp': [], 'udp': [], 'igmp': [], 'other': [],
            'l_tcp': 0, 'l_udp': 0, 'l_igmp': 0, 'l_other': 0,
            'no_tcp': 0, 'no_udp': 0, 'no_igmp': 0, 'no_other': 0}
        # creating constant variables for tables
        table = []
        table_header = ['First Timestamp', 'Last Timestamp', 'Mean Packet Length', 'No of Packets']
        pkt_type = ['tcp', 'udp', 'igmp', 'other']
        pkt_type_clone = pkt_type.copy()
        table_index = [p_type.upper() for p_type in pkt_type]
        try:
            # looping for the time stamp and buffer
            for time_stamp, buff in packets:
                total_buff += len(buff)
                eth = dpkt.ethernet.Ethernet(buff)
                ip_frame = eth.data
                # filtering the packets which are TCP,UDP,IGMP in the looping
                for key, value in packet_type.items():
                    if isinstance(ip_frame.data, value):
                        packet_info[f'no_{key}'] += 1
                        packet_info[key].append(time_stamp)
                        packet_info[f'l_{key}'] += len(buff)
                        no_total += 1
                # filtering the packets which are not TCP,UDP,IGMP
                if is_other(ip_frame):
                    packet_info['no_other'] += 1
                    packet_info['other'].append(time_stamp)
                    packet_info['l_other'] += len(buff)
                    no_total += 1
            # removing types of 0 packets from table
            for value in pkt_type_clone:
                if packet_info[f'no_{value}'] == 0:
                    pkt_type.remove(value)
                    table_index.remove(value.upper())
            # appending data to the table list to show in the table
            for value in pkt_type:
                table.append([
                    dt_from_ts(packet_info[value][0]),
                    dt_from_ts(packet_info[f'{value}'][-1]),
                    packet_info[f'l_{value}']/packet_info[f'no_{value}'],
                    packet_info[f'no_{value}']
                    ])
            #  showing table to users
            print(tabulate(table, headers=table_header, showindex=table_index, tablefmt='fancy_grid'))
            print(f"[*]Total buffer : {total_buff}")
            print(f"[*]No of total packet: {no_total}", '\n')
        except TypeError:
            print('\t', '[!] the inputed arguments have to be list', file=sys.stderr)


def packet_ip_info(packets):
    '''
        Showing overall packet information
    '''
    full_ip_info = {}
    sorted_ip = {}
    with open('output/error_log.txt', 'a', encoding='utf-8') as sys.stderr:
        print('[#] try to show overall packet information', file=sys.stderr)
        try:
            # getting packets by looping the inputed list
            for unused_time_stamp, buff in packets:
                eth = dpkt.ethernet.Ethernet(buff)
                ip_addr_pair = (socket.inet_ntoa(eth.data.src), socket.inet_ntoa(eth.data.dst))
                if (ip_addr_pair) not in full_ip_info.keys():
                    full_ip_info[ip_addr_pair] = [eth.data]
                else:
                    full_ip_info[ip_addr_pair].append(eth.data)
            # counting the length of ip_address_pair's traffics and create new variable
            sorted_ip = {keys: len(values) for keys, values in full_ip_info.items()}
            sorted_ip = dict(sorted(sorted_ip.items(), key=lambda item: item[1]))
            # changing IP dictoionary to List for tabulate
            sorted_ip_traffic = [[f'{k[0]} -> {k[1]}', v] for k, v in sorted_ip.items()]
            table_headers = ['IP Information', 'Numbers of Traffic']
            print(tabulate(reversed(sorted_ip_traffic), headers=table_headers, tablefmt='fancy_grid'))
            return full_ip_info, sorted_ip
        except TypeError:
            print('\t', '[!] need to input one list[] argument', file=sys.stderr)
            return 0, False
        except dpkt.UnpackError as exp:
            print('\t', exp, file=sys.stderr)


def email_image(data_list):
    '''
        Analyzing the image and email from the Packets
    '''
    with open('output/error_log.txt', 'a') as sys.stderr:
        print("[#] trying to show the email and files", file=sys.stderr)
        url_list = []
        img_ext = ['.gif', '.png', '.jpg', '.jpeg']
        email = {'to': [], 'from': []}
        # creating regular expression as constant
        to_pattern = re.compile(r'[\w+\s]*To:*\s?[<]*\w+@\w+.\w+[>]*', re.I)
        from_pattern = re.compile(r'[\w+\s]*From:*\s?[<]*\w+@\w+.\w+[>]*', re.I)
        pattern = {'to': to_pattern, 'from': from_pattern}

        for unused_ts, buff in data_list:
            eth = dpkt.ethernet.Ethernet(buff)
            # checking if packet is TCP
            if isinstance(eth.data.data, dpkt.tcp.TCP):
                ip_frame = eth.data
                src = socket.inet_ntoa(ip_frame.src)
                dst = socket.inet_ntoa(ip_frame.dst)
                tcp = ip_frame.data
                # checking for the SMTP protocol
                try:
                    if tcp.dport in (587, 1687):
                        # decoding data from the tcp packet
                        data = tcp.data.decode('utf-8', 'ignore')
                        for key, value in pattern.items():
                            if not value.match(data) is None:
                                if not value.match(data).group().split('<')[1][0:-1] in email[key]:
                                    email[key].append(value.match(data).group().split('<')[1][0:-1])
                    # checking HTTP or HTPPS by port
                    proto = "http://" if tcp.dport == 443 else "https://"
                    http = dpkt.http.Request(tcp.data)
                    if http.method == "GET":
                        uri = http.uri.lower()
                        for ext in img_ext:
                            if ext in uri:
                                # creating the full url
                                full_link = f"{proto}{http.headers['host']}{uri}"
                                # appeding full_url and base to the url_list
                                url_list.append((full_link, os.path.basename(uri)))
                                print(f"[*]{src} downloaded {os.path.basename(uri)} from {dst}")
                                print(f"[*]Full url: {full_link}")
                                print(f"[*]File Name: {os.path.basename(uri)}",'\n')
                except dpkt.UnpackError as exp:
                    print('\t', exp, file=sys.stderr)
        if len(url_list) == 0:
            print('[!] There is no file download in these packets')
        # filtering the empty list for not to show empty table
        if len(email['from']) != 0 and len(email['to']) != 0:
            header_list = [
                'Emails detect To: format',
                'Emails detect From: format']
            print(tabulate(email, headers=header_list, tablefmt='fancy_grid'))
        else:
            print('[!] Emails not found in these packets', '\n')
