'''
    Run This File As main Program
'''
import sys
import packet_information as pkt_info
import graph_visualizer as gv


def main():
    '''
        Main Function
        can add for the additional .pcap information
    '''
    try:
        with open('output.txt', 'w', encoding='utf-8') as sys.stdout:
            packets = pkt_info.prase_packets(sys.argv[1])
            pkt_info.show_summerize_table(packets)
            pkt_info.email_image(packets)
            unused_fullpkt, packets_count = pkt_info.packet_ip_info(packets)
            gv.graph_visulize(packets_count)
            gv.timestamp_linechart(packets)
    except IndexError:
        print('[!] need to input one argument')
    except TypeError:
        print('[!] need to input one argument to function')


if __name__ == "__main__":
    main()
