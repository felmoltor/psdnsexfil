#!/usr/bin/env python

from prompt_toolkit import prompt
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from optparse import OptionParser
from DNSServer import *
from datetime import date

def parse_options():
    parser = OptionParser()
    parser.add_option("-i", "--interface", dest="interface",
                    help="IP address of the interface to listen for incoming DNS packets (Def: None)", default=None)
    parser.add_option("-p", "--port", dest="port",
                    help="Port number of the interface to listen for incoming DNS packets (Def: 53)", default=53)
    parser.add_option("-d", "--domain", dest="domain",
                    help="Domain name to answer to (Def: None)", default=None)
    parser.add_option("-r", "--ref-size", dest="reference_size",
                    help="Reference ID size embedded in the DNS queries (Def: 5 bytes/chars)", default=5)
    parser.add_option("-R", "--reqnum-size", dest="requestnum_size",
                    help="Request number size embedded in the DNS queries (Def: 5 bytes/chars)", default=6)
    parser.add_option("-P", "--pcap", dest="pcap",
                    help="pcap file to read from. This option is mutually exclusive with -i", default=None, metavar="FILE")
    parser.add_option("-s", "--source", dest="source",
                    help="Source IP address from where the data is coming (Def: None)", default=None)
    parser.add_option("-e", "--encryption", dest="encryption",
                    help="Encryption method used [NONE,AES,XOR] (Def: NONE)", choices = ("NONE","AES","XOR"), default="NONE")
    parser.add_option("-a", "--password", dest="password",
                    help="Password used to encrypt the content (Def: None)", default=None)      
    parser.add_option("-o", "--output", dest="output",
                    help="Output directory to drop the files to (Def: output)", default="./output/")  
    parser.add_option("-l", "--loglevel",
                    type = "choice", choices = ("DEBUG","INFO","WARNING","ERROR","CRITICAL"),
                    dest="loglevel", default="INFO",
                    help="Log level. Default 'INFO'. Choices [DEBUG,INFO,WARNING,ERROR,CRITICAL]")

    (options, args) = parser.parse_args()

    # Test if the interface exists
    if options.interface is not None:
        if not options.interface in ifaces:
            parser.error("The interface (-i) you selected to listen on is invalid. Try again with a valid interface name")

    return (options,args)

########
# MAIN #
########

def main():
    (options,args)=parse_options()

    # Create the log folder if it does not exists
    if not os.path.exists("./logs"):
        os.mkdir("./logs")
    today=(date.today()).strftime("%Y%m%d")
    logfile="./logs/%s.log" % today

    dns=DNSServer(logfile=logfile,loglevel=options.loglevel,output_folder=options.output)
    
    if (options.port is not None):
        dns.port=int(options.port)
    if (options.domain is not None):
        dns.domain=options.domain
    if (options.pcap is not None):
        dns.pcap=options.pcap
    if (options.source is not None):
        dns.source=options.source
    if (options.reference_size is not None):
        dns.reference_size=options.reference_size
    if (options.requestnum_size is not None):
        dns.requestnum_size=options.requestnum_size
    if (options.encryption is not None):
        dns.encryption=options.encryption
    if (options.password is not None):
        dns.password=options.password
    if (options.interface is not None):
        dns.interface=options.interface
    
    # Now, starts sniffing 
    dns.start()    
    dns.log("Server running in the background.",level=logging.INFO)
    # Define REPL autocompleter
    # actions_completer = WordCompleter(['ls', 'cmd','stats', 'get', 'put', 'exit', 'quit','agent','pcap'],
    #                          ignore_case=True)
    # agent_completer = WordCompleter(["status","heartbeat","ls","set","get","taskslist","whoami","id"],
    #                          ignore_case=True)
    # getset_completer = WordCompleter(["encryption","compression","filenames","polling"],ignore_case=True)
    
    # Loop infinitely until quit or Ctrl+C is typed
    # stop=False
    # while (not stop):
    #     command=prompt("> ", 
    #         history=FileHistory('logs/repl_acction_history.txt'),
    #         auto_suggest=AutoSuggestFromHistory(),
    #         completer=actions_completer,
    #         complete_while_typing=True)

    #     command=command.lower()
    #     if (command=="ls"):
    #         # Execute ls in the server (in this machine)
    #         print("STUB: Executing ls on server")
    #     elif (command=="cmd"):
    #         print("STUB: Sending command to execute to the agent with the next heartbeat answer")
    #     elif (command=="stats"):
    #         n_completed = list([t.completed for t in dns.transactions]).count(True)
    #         print("Getting stats from the DNS server")
    #         print("* N# Transactions: %s" % len(dns.transactions))
    #         print("** N# Completed: %s" % len(dns.transactions))
    #         print("** N# Ongoing: %s" % len(dns.transactions-n_completed))
    #     elif (command=="get"):
    #         print("STUB: Retrieving a file from the agent-side")
    #     elif (command=="put"):
    #         print("STUB: Pushing a file to the agent")
    #     elif (command=="agent"):
    #         print("STUB: Listing agent commands")
    #     elif (command=="exit" or command=="quit"):
    #         print("Stoping the server")
    #         dns.stop()
    #         break

    print("Done")
        

    

if __name__ == '__main__':
    main()
else:
    print("Sorry, this file is intended to be invoked directly, cannot be imported")