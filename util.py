"""
helpers for awssh/awscp
"""

# XXX search for, read .awsshrc file???
# XXX honor REGIONS (loop for all, use domain/user/key values)
# XXX override DEFUSER/KEY from environment?
# XXX handle ~ in KEYDIRS
# XXX perform prefix match on aliases?
# XXX merge host & asg "auks" for prefix match???

# standard
import os
import sys
import socket

# pypi
try:
    import boto.ec2
    import boto.ec2.autoscale
    HAVE_BOTO = True
except:
    HAVE_BOTO = False

# local
import settings

# HOSTS tuple entries
H_NAME, H_USER, H_KEY = 0, 1, 2

# AWS_ASGS tuple entries
A_NAME, A_REGION, A_USER, A_KEY = 0, 1, 2, 3

# made it a class to hold "debug" setting!
class Util(object):
    def __init__(self, debug):
        self.debug = debug

    def exec_(self, args, check=False):
        """
        exec ssh/scp
        """
        if not check:
            # supress known_hosts file warnings/additions
            # (ASG instances are transient)
            args = [
                   args[0],
                   '-o', 'StrictHostKeyChecking=no',
                   '-o', 'UserKnownHostsFile=/dev/null',
                   '-o', 'LogLevel=error'] + list(args[1:])
        os.execl(args[0], *args)

    def fork(self, *pos, **kws):
        """
        fork and exec ssh/scp
        """
        pid = os.fork()
        if pid == 0:
            try:
                self.exec_(*pos, **kws)
            except:
                pass
            return -1
        else:
            pid, status = os.waitpid(pid, 0)
            return os.WEXITSTATUS(status)

    def _check_hostname(self, name, fam=socket.AF_INET):
        """
        @param str name to check if a hostname
        @param int fam AF_INET returns IPv4 only; AF_INET6 6 only; 0 returns 4 & 6
        @return list of addresses (as strings)
        """
        # returns hosts file entries as well as DNS
        try:
            addrs = socket.getaddrinfo(name, 22, fam, socket.SOCK_STREAM) # XXX inside try
            return [sockaddr[0] for family, socktype, proto, canonname, sockaddr in addrs]
        except:
            return []

    def fetch_asgs(self, region):
        """
        @param str region to fetch ASGs from
        @return list of (asg_name, [instance_name,.....], region)
        """
        try:
            asconn = boto.ec2.autoscale.connect_to_region(region)
        except:
            if HAVE_BOTO:
                sys.stderr.write("could not connect to AWS: do you have ~/.aws/credentials?\n")
            elif self.debug:
                print "boto not installed"
            return []
        groups = asconn.get_all_groups()
        # XXX skip empties???
        return [(group.name, [ii.instance_id for ii in group.instances], region) for group in groups
                if group.instances]

    def _pick_user_key(self, *uks):
        """
        @param uks (user, keyfile) tuples
        @return (user, keyfile) -- always a matched pair
        likely still needs work????
        """
        if self.debug: print "pick_user_key", uks
        for user, key in uks:
            if self.debug: print "  checking", (user, key)
            if user is None and key is None:
                continue
            # if keyfile given, must exist!
            if key:
                kf = self.find_keyfile(key)
                if not kf:
                    if self.debug: print "  key file not found", key
                    continue
                key = kf
                break
            # '' means use logged-in user
            # None accepted for key (use key from ~/.ssh)
            if user is not None:
                break
        else:
            user, key = (settings.DEFUSER, settings.DEFKEY)
        ret = (user, key)
        if self.debug: print "  returning", ret
        return ret

    def _instance_auks(self, names, region, user, key):
        """
        Look up AWS instance IP addresses
        @param names list of instance names (i-XXXX....)
        @param region str region name
        @param user str user from AWS_ASGS, if any
        @param key str user from AWS_ASGS, if any
        @return list of (ip_addr, (user, keyfile), id)
        """
        try:
            ec2conn = boto.ec2.connect_to_region(region)
        except:
            if HAVE_BOTO:
                sys.stderr.write("could not connect to AWS\n")
            elif self.debug:
                print "boto not installed"
            return []
        instances = ec2conn.get_only_instances(instance_ids=names)
        return [(ii.ip_address,
                 self._pick_user_key(
                     (user, key),
                     # only use DEFUSER if key_name is non-empty!
                     (ii.key_name and settings.AWS_DEFUSER or None, ii.key_name)),
                 ii.id)
                for ii in instances]

    def find_auks(self, name, region):
        """
        @param str name of alias, host or asg (may be prefix)
        @param str region to check
        @return list of (addr, (user, key), id)
        """
        # backwards compatibility:
        if isinstance(settings.ALIASES, dict):
            settings.ALIASES = settings.ALIASES.items()

        # look for prefix matches in ALIASES:
        matches = [item for item in settings.ALIASES if item[0].startswith(name)]
        if len(matches) == 1:
            if self.debug: print "ALIAS match:", matches[0]
            name = matches[0][1]
        elif self.debug:
            if len(matches) > 1:
                print "multiple ALIAS matches:", matches
            else:
                print "no ALIAS matches"

        hosts = self._check_hostname(name)
        if self.debug: print "hosts", hosts
        if hosts:
            # look for exact match in HOSTS for user & key file
            for host, u, k in settings.HOSTS:
                if host == name:
                    if self.debug: print "HOST match:", host, u, k
                    return [(hh, self._pick_user_key((u, k)), None) for hh in hosts]
            # XXX look for wildcard (fnmatch) in HOSTS for user/key
            return [(hh, (settings.DEFUSER, settings.DEFKEY), None) for hh in hosts]

        # see if a prefix of a single HOSTS entry
        matches = [item for item in settings.HOSTS if item[H_NAME].startswith(name)]
        if self.debug: print "HOSTS matches", matches
        if len(matches) == 1:
            h = matches[0]
            print "matched HOST", h[H_NAME]
            return [(hh, self._pick_user_key((h[H_USER], h[H_KEY])), None)
                    for hh in self._check_hostname(h[H_NAME])]

        # check as hostname in DOMAINS
        for domain in settings.DOMAINS:
            hosts = self._check_hostname(name)
            if hosts:
                # XXX look for wildcard (fnmatch) in HOSTS for user/key
                return [(hh, (settings.DEFUSER, settings.DEFKEY), None) for hh in hosts]

        ################
        # see if a prefix of a single AWS_ASGS entry, if so, use full name, region, user, key

        matches = [item for item in settings.AWS_ASGS if item[0].startswith(name)]
        if self.debug: print "AWS_ASGS matches", matches
        uu = kk = None
        if len(matches) == 1:
            aa = matches[0]
            name = aa[A_NAME]
            if not region:          # no region from command line
                region = aa[A_REGION] # use region from match
            uu, kk = aa[A_USER], aa[A_KEY]
        ################
        # look for AWS Auto-Scale Groups in all known regions
        # if an AWS_ASGS entry was found above, use the region, if any

        if region:
            regions = [region]
        else:
            regions = settings.AWS_REGIONS.keys()

        # collect ASG names from all regions
        asgs = []
        for rr in regions:
            asgs.extend(self.fetch_asgs(rr))

        # get prefix matches
        matches = [asg for asg in asgs if asg[0].startswith(name)]
        if self.debug: print "active asg matches", matches
        if len(matches) == 1:
            aa = matches[0]
            name = aa[0]
            instances = aa[1]
            rr = aa[2]
            print "matched ASG", rr, name
            # XXX look for REGIONS[region] for default domain, user, key
            # (currently always fetches IP addresses)
            return self._instance_auks(instances, rr, uu, kk)
        elif len(matches) > 1:
            print "ambiguous:", ' '.join([aa[0] for aa in matches])
            # break loop?
        return []

    def find_keyfile(self, name):
        """
        @param str name to check for a keyfile for
        @return str path, if keyfile found, else None
        """
        if not name:
            return None
        if os.path.isfile(name):
            return name
        pem = None
        if '.pem' not in name:
            pem = name + '.pem'
            if os.path.isfile(pem):
                return pem
        for dir in settings.KEYDIRS:
            p = os.path.join(dir, name)
            if os.path.isfile(p):
                return p
            if pem:
                p = os.path.join(dir, pem)
                if os.path.isfile(p):
                    return p
        return None

if __name__ == '__main__':
    for x in host_list(sys.argv[1]):
        print x
