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
            # supress known_hosts warnings/additions
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
        take a name, check if a hostname
        return list of addresses (as strings)
        fam=AF_INET returns IPv4 only; AF_INET6 6 only; 0 returns 4 & 6
        """
        # returns hosts file entries as well as DNS
        try:
            addrs = socket.getaddrinfo(name, 22, fam, socket.SOCK_STREAM) # XXX inside try
            return [sockaddr[0] for family, socktype, proto, canonname, sockaddr in addrs]
        except:
            return []

    def fetch_asgs(self, region):
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
        args: (user, keyfile) tuples
        currently always returns matched pair
        XXX still needs work????
        """
        if self.debug: print "pick_user_key:"
        for uk in uks:
            if self.debug: print uk
            # keyfile must exist!
            if uk[1]:
                kf = self.find_keyfile(uk[1])
                if not kf:
                    if self.debug: print uk[1], "not found"
                    continue
                return (uk[0], kf)
            # '' means use logged-in user
            # None accepted for key (use key from ~/.ssh)
            if uk[0] is not None:
                if self.debug: print "returning", uk
                return uk
        uk = (settings.DEFUSER, settings.DEFKEY)
        if self.debug: print "returning", uk
        return uk

    def _instance_auks(self, names, region, user, key):
        """
        Look up AWS instance IP addresses
        @param names list of instance names (i-XXXX....)
        @param region str region name
        @param user str user from AWS_ASGS, if any
        @param key str user from AWS_ASGS, if any
        @return [(addr, (user, keyfile)),...]
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
        return [(ii.ip_address, self._pick_user_key((user, key),
                                                    (settings.AWS_DEFUSER, ii.key_name)))
                for ii in instances]

    def find_auks(self, name, region, debug=True):
        """
        return address/user/key matches for name (in region)
        @param name str name of alias, host or asg (may be prefix)
        @return [(addr,(user,key)),....]
        """
        # backwards compatibility:
        if isinstance(settings.ALIASES, dict):
            settings.ALIASES = settings.ALIASES.items()
        matches = [item for item in settings.ALIASES if item[0].startswith(name)]
        if len(matches) == 1:
            if self.debug: print "ALIAS match:", matches[0]
            name = matches[0][1]

        hosts = self._check_hostname(name)
        if hosts:
            # look for exact match in HOSTS for user & key file
            for host, u, k in settings.HOSTS:
                if host == name:
                    return [(hh, self._pick_user_key((u, k))) for hh in hosts]
            # XXX look for wildcard (fnmatch) in HOSTS for user/key
            return [(hh, (None, None)) for hh in hosts]

        # see if a prefix of a single HOSTS entry
        matches = [item for item in settings.HOSTS if item[H_NAME].startswith(name)]
        if debug: print "HOSTS matches", matches
        if len(matches) == 1:
            h = matches[0]
            print "matched HOST", h[H_NAME]
            return [(hh, self._pick_user_key((h[H_USER], h[H_KEY])))
                    for hh in self._check_hostname(h[H_NAME])]

        # check as hostname in DOMAINS
        for domain in settings.DOMAINS:
            hosts = self._check_hostname(name)
            if hosts:
                # XXX look for wildcard (fnmatch) in HOSTS for user/key
                return [(hh, (None, None)) for hh in hosts]

        ################
        # see if a prefix of a single AWS_ASGS entry, if so, use full name, region, user, key

        matches = [item for item in settings.AWS_ASGS if item[0].startswith(name)]
        if debug: print "AWS_ASGS matches", matches
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
        if debug: print "active asg matches", matches
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
            # XXX display region??
            print rr, "ambiguous:", ' '.join([aa[0] for aa in matches])
            # break loop?
        # XXX display error: list asgs???
        return []

    def find_keyfile(self, name):
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
