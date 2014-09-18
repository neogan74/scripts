#!/usr/bin/python
import optparse
import sys
import traceback
from getpass import getpass
from zabbix_api import ZabbixAPI, ZabbixAPIException

def get_options():
    """ command-line options """

    usage = "usage: %prog [options]"
    OptionParser = optparse.OptionParser
    parser = OptionParser(usage)

    parser.add_option("-s", "--server", action="store", type="string", \
            dest="server", help="Zabbix Server URL (REQUIRED)")
    parser.add_option("-u", "--username", action="store", type="string", \
            dest="username", help="Username (Will prompt if not given)")
    parser.add_option("-p", "--password", action="store", type="string", \
            dest="password", help="Password (Will prompt if not given)")

    options, args = parser.parse_args()

    if not options.server:
        show_help(parser)

    if not options.username:
        options.username = raw_input('Username: ')

    if not options.password:
        options.password = getpass()

    # apply clue to user...
    if not options.username and not options.password:
        show_help(parser)

    return options, args

def show_help(p):
    p.print_help()
    print "NOTE: Zabbix 1.8.0 doesn't check LDAP when authenticating."
    sys.exit(-1)

def errmsg(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(-1)

if  __name__ == "__main__":
    #options, args = get_options()
    #206
    #zapi = ZabbixAPI(server="http://192.168.56.101/206") #log_level=1
    zapi = ZabbixAPI(server="http://10.211.55.3/225/") #log_level=1
    #zapi = ZabbixAPI(server="http://192.168.110.55/zabbix/") #log_level=1
    try:
        zapi.login("Admin","zabbix")
        #zapi.login("Zabbix-Support","m8FPK;666")
        #print "Zabbix API Version: %s" % zapi.api_version()
        #print "Logged in: %s" % str(zapi.test_login())
    except ZabbixAPIException, e:
        sys.stderr.write(str(e) + '\n')
    try: 
        #for host in zapi.item.get( {"hostid": "10017", "search" : {"key_": "system.uptime"}}):

### [ "jmx[org.hornetq:module=Core,type=Queue,address=\"billing-invoicing-result\",name=\"billing.invoicing.result-v2#openapi.PaymentTransactionBusinessPartnerNotification-unknown\"][MessageCount]" ],[\n]"

        #for host in zapi.item.get( {"output" : "extend", "hostids": "10084"}):
         #   print host
          #  print ""
        #for host2 in zapi.history.get( { "history":0, "output":"extend", "sortfield":"clock" ,"history":"3",  "hostids": "10084", "itemids" :"23316", "limit": "10"}):
            #print host2
        #a = zapi.history.get({"output":"extend","history":0,"itemids":["23303","23306"],"time_from":"1397658775"})
 #       a = zapi.host.get({"filter":{"host":["mons.iskranet.ru"]}})
        #a  = zapi.host.delete({"hostid":10088})
#        print a
 #       a = zapi.template.update({"templateid":18111,"macros":["{$test}":"111","{$test2}":333]})
#        print a
        #a = zapi.template.update({"templateid":10056,"macros":[{"{$TEST1}":1,"{$GGG}":1}]})
        #a = zapi.configuration.export({"options":{"hosts":["10089"],"format":"json"}})
        a = zapi.hostinterface.get({"hostids":10105,"output":"extend"})
        #a = zapi.history.get({"output":"extend","hostids":10084, "time_from":})
        # a = zapi.usergroup.get({"output":['name']}) # get all group names
        #a = zapi.usergroup.get({"output":"extend","filer": {"usrgrpid":"7"}}) # get permissions for some group
        #a = zapi.host.update({"output":"extend","hostid":10381,"proxy_hostid":10117})
        #a = zapi.history.get({"output":"extend","history":2,"itemsids":"23816","limit":10})
        #a = zapi.trigger.get({'host':'Zabbix server'})
        print a
        #b = zapi.hostinterface.create({"hostid":10105,"dns":"","port":12,"ip":"127.0.0.99","main":0,"type":1,"useip":1})
        b = zapi.host.update({"hostid":10106,"interfaces":[{"port":10050, "type":1,"main":1},{"dns":"","ip":"127.0.0.1", "main":1,"port":151, "type":2,"useip":1}]})
        #b = zapi.hostinterface.replacehostinterfaces({"hostid":10105,"interfaces":[{"dns":"","ip":"127.0.0.1", "main":1,"port":10050, "type":1,"useip":1},{"dns":"","ip":"127.0.0.1", "main":1,"port":161, "type":2,"useip":1},{"dns":"","ip":"127.0.0.1", "main":1,"port":1234, "type":3,"useip":1},{"dns":"","ip":"127.0.0.1", "main":1,"port":1611, "type":4,"useip":1}]})
        print b
        c = zapi.hostinterface.get({"hostids":10105})
        print c
        '''
        Create host function
        '''
        def create_host(host_name,templateids):
            a = zapi.host.create({'host':host_name,"interfaces":[{"type":1,"main":1,"useip":1,"ip":"127.0.0.1","dns":"","port":10050}],"groups":[{"groupid":2}],"templates":[{"templateid":templateids}]})
            print a
        '''MASS Creating hosts'''
        def mass_creating_host(n):
            for x in range(n):
                #print "NewHost"+str(x)
                create_host("TheNewestHost"+str(x),10050)

        #mass_creating_host(30)


        def get_hostids(search_name):
            b = zapi.host.get({'search':{"host":search_name}})
            #print b
            l=[]
            for i in b:
                l.append(i["hostid"])
            return l      

        #print get_hostids("NewHost")  

        '''
        Host mass update function
        '''
        def hosts_massadd(hostids,dest_group):
            for x in hostids:
                a = zapi.host.massadd({'hosts':[{'hostid':x}],"groups":[{"groupid":dest_group}]})
            print a

        #hosts_massadd(l,6)

        def Hostgroup_massadd(hostids,dest_group):
            for x in hostids:
                a = zapi.hostgroup.massadd({"groups":[{'groupid':dest_group}],"hosts":[{"hostid":x}]})

        #Hostgroup_massadd(l,7)

        def Hostgroup_create(n):
            for x in range(n):
                f = "Grouppppp"+str(x)
                print f
                a = zapi.hostgroup.create({"name":f})

        #Hostgroup_create(500)
        def create_user(n):
            for x in range(n):
                zapi.user.create({ "usrgrps":[{"usrgrpid":113}],"alias":"tess"+str(x),"passwd": "123",})

        def usergroup_create(n):
            for x in range(n):
                zapi.usergroup.create({"name":"tess"+str(x)})
    except ZabbixAPIException, e:
        sys.stderr.write(str(e) + '\n')