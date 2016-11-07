#!/usr/bin/env python
import sys
import os
from linode import Api
import yaml
import pexpect
import time
"""
deploy.py
Created by Anthony Velardi on 06-07-2016
"""
def argchk():
    if '-h' in sys.argv or '--help' in sys.argv or len(sys.argv) < 4:
        print 'usage:deploy.py [DCID] [Honeypot] [node name]'
        print '\nHoneypot options:\n shockpot\n dionaea\n kippo\n snort\n suricata\n cowrie\n shockpotsinkhole'
        print '\ndcids:'
        print """ 2-Dallas, TX, USA
 3-Fremont, CA, USA
 4-Atlanta, GA, USA
 6-Newark, NJ, USA
 7-London, England, UK
 8-Tokyo, JP
 9-Singapore, SG
 10-Frankfurt, DE"""
        print "\nMoar to come"
        sys.exit()
    dcid = sys.argv[1]
    try:
        dcid = int(dcid)
    except:
        print "DCID error: integer req'd found something else :("
        sys.exit()
    return dcid
    
    
def makelinode():
    dcid = argchk()
    print "Welcome to the automated honeypot deployment tool"
    with open('config.yaml','r') as f:
        config = yaml.load(f.read())
    api = Api(config['apikey'])
    print "Creating new linode"
    newlinode = api.linode.create(dcid,1)
    lid = int(newlinode['LinodeID'])
    print "New linode created! Linodeid:" + str(newlinode['LinodeID'])
    print "Creating Disks..."
    did = int(config['distid'])
    ld = api.linode.disk.createfromdistribution(LinodeID=lid,DistributionID=did,Label=sys.argv[3],Size=24000,rootPass=config['sshpass'],rootKey=config['sshkey'])
    print "OS Disk created"
    lsd = api.linode.disk.create(LinodeID=lid,DistributionID=did,Label='Swap',Type='swap',Size=256)
    print "Swap created"
    #latest 64bit is 138
    disklist = str(ld['DiskID']) + ',' + str(lsd['DiskID'])
    lc = api.linode.config.create(LinodeID=lid,KernelID=138,Label=sys.argv[3],DiskList=disklist,helper_distro=1,helper_network=1)
    print "Config profile generated"
    api.linode.boot(LinodeID=lid,ConfigID=lc['ConfigID'])
    print "Linode boot job inserted"
    api.linode.update(LinodeID=lid,Label=sys.argv[3],lpm_displayGroup=config['displaygroup'])

    return lid,config
    

def initial(lid,config):
    api = Api(config['apikey'])
    lips = api.linode.ip.list(LinodeID=lid)
    for ip in lips:
         if ip['ISPUBLIC']:
             linip = ip['IPADDRESS']
    print "Linode ip is " + linip
    hpcom = whichhoneypot(sys.argv[3],config['defaulthp'])
    print "Pausing for 30 seconds for boot"
    for i in range(30):
        s = 30-i
        sys.stdout.write("seconds left: %s \r" % s)
        sys.stdout.flush()
        time.sleep(1)
    print "Connecting via ssh for configuration"
    s = pexpect.spawn('ssh root@' + linip)
    needpass=True
    try:
        s.expect("password:")
    except:
        s.close()
        print "Oh no! Looks like it's not ready yet. Looping back"
        initial(lid,config)
    s.sendline(config['sshpass'])
    print "Logged in via ssh, config happening now"
    s.expect("root@ubuntu:~#")
    s.sendline("""echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4""")
    s.sendline("wget " + config['initscripturl'])
    s.expect("root@ubuntu:~#")
    print "Downloaded initial config script before:"
    s.sendline("chmod +x init.sh")
    s.expect("root@ubuntu:~#")
    s.sendline("./init.sh")
    s.expect("root@ubuntu:~#")
    print "Initial config script done, setting hostname etc"
    s.sendline("hostnamectl set-hostname " + sys.argv[3])
    s.expect(":~#", timeout=120)
    s.sendline("echo " + sys.argv[3] + " > /etc/hostname")
    s.expect(":~#", timeout=120)
    s.sendline("hostname -b " + sys.argv[3])
    print "hostname set"
    s.expect(":~#", timeout=120)
    s.sendline("mkdir ~/.ssh && touch ~/.ssh/authorized_keys && echo " + config['sshkey'] + " >> ~/.ssh/authorized_keys")
    s.expect(":~#", timeout=120)
    s.sendline("sed -i 's/PermitRootLogin yes/PermitRootLogin without-password/' /etc/ssh/sshd_config")
    s.expect(":~#", timeout=120)
    #greedy sed
    s.sendline("sed -i 's/.*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config")
    s.expect(":~#", timeout=120)
    print "key auth done"
    s.sendline("service ssh reload")
    print "Init script and config has finished, time to add it to the pool"
    print "This will take a minute"
    s.expect(":~#", timeout=120)
    s.sendline(hpcom)
    s.expect(":~#", timeout=120)
    print "Got the script!"
    s.sendline("chmod +x deploy.sh")
    s.expect(":~#", timeout=120)
    #answer = str(raw_input("Final deploy script not run. Want an interactive shell?[y/n]"))
    # if answer == "y":
    #     s.interact()
    # else:
    #     s.close()
    #this is to verify it works
    s.close()
    s = pexpect.spawn('ssh root@' + linip)
    s.expect(":~#")
    s.sendline("tmux new -s config -d './deploy.sh http://beekeeper.velardi.io bxWAO7ND'")
    s.expect(":~#")
    s.close()
    return linip
    

    
####This should have been a base url import from the yaml, and is a failure on my part. Sorry.
def whichhoneypot(uhp,dhp):
    if "snort" in uhp:
        print "Making a snort box"
        return """wget "https://MHN-URL/script/?text=true&script_id=3" -O deploy.sh"""
    if "kippo" in uhp:
        print "Making a kippo box"
        return """wget "https://MHN-URL/api/script/?text=true&script_id=10" -O deploy.sh"""
    if "shockpot" in uhp:
        print "Making a shockpot box"
        return """wget "https://MHN-URL/api/script/?text=true&script_id=15" -O deploy.sh"""
    if "dionaea" in uhp:
        print "Making a dionaea box"
        return """wget "https://MHN-URL/api/script/?text=true&script_id=4" -O deploy.sh"""
    if "glastopf" in uhp:
        print "Making a glastoph box"
        return """wget "https://MHN-URL/api/script/?text=true&script_id=8" -O deploy.sh"""
    if "suricata" in uhp:
        print "Making a suricata box"
        return """wget "https://MHN-URL/api/script/?text=true&script_id=13" -O deploy.sh"""
    if "cowrie" in uhp:
        print "Making a cowrie box"
        return """wget "https://MHN-URL/api/script/?text=true&script_id=14" -O deploy.sh"""
    if "shockpotsinkhole" in uhp:
        print "Making a shockpot sinkhole box"
        return """wget "https://MHN-URL/api/script/?text=true&script_id=1" -O deploy.sh"""
    else:
        print "Couldn't find a script for the honeypot you asked for :( Defaulting to config default"
        whichhoneypot(dhp,dhp)

def killit(lid,config):
    #built this in for testing, can be removed if ya want
    x = str(raw_input("Wanna kill the linode?[y/n]"))
    if x == "y":
        api = Api(config['apikey'])
        api.linode.delete(LinodeID=lid,skipChecks=True)
        print "Linode deleted!"
    else:
        print "Not deleting the linode!"

if __name__ == "__main__":
    lid,config = makelinode()
    linip = initial(lid,config)
    print '--------------------\nAll done! Linode IP: ' + linip + '\n--------------------'
    #killit(lid,config)