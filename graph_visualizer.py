'''
    This moudule show the packets with graph to check the packets easily
'''
import sys
import statistics as stats
import dpkt
import matplotlib.pyplot as plt
import networkx as nx


def graph_visulize(data):
    '''
        Creating Graph to recognize easily the attacker's traffic
    '''
    graph = nx.DiGraph()
    with open('output/graph_output.txt', 'w') as sys.stdout:
        try:
            for key, value in dict(data).items():
                # creating the color scheme for graph
                if value < 50:
                    if value < 10:
                        print(f'[!]{key[0]} --> {key[1]} weakly connected')
                    colour = 'black'
                elif value < 100:
                    colour = 'g'
                elif value < 200:
                    colour = 'y'
                    print(f'[!]{key[0]} --> {key[1]} strongly connected')
                else:
                    colour = 'r'
                    print(f'[!]{key[0]} --> {key[1]} strongly connected')
                graph.add_edge(key[0], key[1],  width=value/100*2, color=colour)
            # getting width and colour list from the graph edges
            colours = nx.get_edge_attributes(graph, 'color').values()
            width = nx.get_edge_attributes(graph, 'width').values()
            # choosing the layout for the graph
            pos = nx.planar_layout(graph)
            nx.draw(graph,
                    pos,
                    edge_color=colours,
                    width=tuple(width),
                    with_labels=True,
                    node_color='lightgreen')
            nx.draw_networkx_edge_labels(graph, pos, edge_labels=data)
            plt.show()
            # showing number of nodes and edges to the terminal for the user
            print(f'[*]number of nodes: {len(graph)}')
            print(f'[*]number of edges: {graph.number_of_edges()}')
        except TypeError:
            print('[!]graph_visualize() need to be inputed one dict')
        except dpkt.UnpackError as exp:
            print(exp)


def timestamp_linechart(pcap_list):
    '''
        Showing line graph to user to check which interval has most traffic
    '''
    # opening .txt file for error or exception logs.
    with open('output/error_log.txt', 'a') as sys.stderr:
        print(
            '[#] showing line chart of traffic against the time',
            file=sys.stderr)
        try:
            no_intervel = 10
            # duration of the pcap file
            timestamp_difference = pcap_list[-1][0]-pcap_list[0][0]
            # calculating the one intervel
            one_intervel = timestamp_difference/no_intervel
            timestamp_counter = pcap_list[0][0]
            interval_counter = 1
            buff_dict = {}
            timestamp_list = []
            for (time_stamp, buff) in pcap_list:
                if timestamp_counter+one_intervel >= time_stamp:
                    if interval_counter not in buff_dict:
                        buff_dict[interval_counter] = [buff]
                        timestamp_list.append(time_stamp)
                    else:
                        buff_dict[interval_counter].append(buff)
                else:
                    timestamp_counter += one_intervel
                    interval_counter += 1
            traffic_intervals = {
                keys: len(values) for keys, values in buff_dict.items()}
            # finding mean number of packets per interval
            mean_list = [values for keys, values in traffic_intervals.items()]
            mean = stats.mean(mean_list)
            threshold = mean+stats.stdev(mean_list)

            plt.plot(traffic_intervals.keys(), traffic_intervals.values())
            plt.title('the number of packets against time'.upper())
            plt.xlabel('time intervel'.upper())
            plt.ylabel('no of packet'.upper())
            plt.axhline(y=threshold, color='r', linestyle='--')
            plt.grid(True)
            plt.show()

        except TypeError:
            print(
                '\t',
                '[!] need to input list with (timestamp and buffer)',
                file=sys.stderr)
