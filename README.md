# filterpcap
Fast pcap voip filters

This little tool will take in a packet capture and search it for calls containing specific features (i.e. called phone number, SIP call id, or calls containing SIP packets with a certain status code).  The found calls will be output to separate files, and zipped if there are more than one file.

## Some example usages

    # Find calls to 4145341207
    filterpcap file.pcap --toNumber=4145341207

    # Find call with SIP callId 'xyz'
    filterpcap file.pcap --callId=xyz

    # Find all calls with SIP packets that have status code 488
    filterpcap file.pcap --sipCode=488