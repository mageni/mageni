##############################################################################
# OpenVAS Vulnerability Test
# $Id: portscan-strobe.nasl 11665 2018-09-28 07:14:18Z cfischer $
#
# NASL wrapper around strobe portscanner
#
# Author:
# Vlatko Kosturjak <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################
#
# TODO:
# - report back banners grabbed
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80009");
  script_version("$Revision: 11665 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 09:14:18 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-10-26 10:11:20 +0100 (Sun, 26 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("strobe (NASL wrapper)");
  script_category(ACT_SCANNER);
  script_copyright("This script is Copyright (C) 2008-2010 Vlatko Kosturjak");
  script_family("Port scanners");
  script_dependencies("toolcheck.nasl", "ping_host.nasl");
  script_mandatory_keys("Tools/Present/strobe");

  #  script_add_preference(name:"Strobe timeout", type:"entry", value:"");
  #  script_add_preference(name:"Strobe number of sockets in parallel", type:"entry", value:"");
  #  script_add_preference(name:"Strobe local port to bind outgoing requests", type:"entry", value:"");
  #  script_add_preference(name:"Disable usage of getpeername", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This plugin runs strobe to find open ports.
  Strobe is a small TCP port scanner.

  This wrapper is deprecated due to the non-free license of strobe.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

ip = get_host_ip();
esc_ip = ""; l = strlen(ip);
for (i = 0; i < l; i ++)
  if (ip[i] == '.')
    esc_ip = strcat(esc_ip, "\.");
  else
    esc_ip = strcat(esc_ip, ip[i]);

prange = get_preference("port_range");
if (! prange) prange = "1-65535";

portrangelist=split(prange,sep:",",keep:FALSE);

size=max_index(portrangelist);

# Remove UDP elements.  Strip leading "T:" off TCP elements.

i=0; j=0;

new_portrangelist = make_array ();
tcp = 1;

for (i=0; i<size; i++) {
	if (substr (portrangelist[i], 0, 1) == "U:") {
		# Skip UDP elements.
		tcp = 0;
	} else if (substr (portrangelist[i], 0, 1) == "T:") {
		# Strip off leading "T:".
		new_portrangelist[j] = substr (portrangelist[i], 2);
		j++;
		tcp = 1;
	} else if (tcp == 1) {
		new_portrangelist[j] = portrangelist[i];
		j++;
	}
}

portrangelist = new_portrangelist;

# optimize list of ports; assumes sorted array
i=0; j=0; l=0;

for (i=0; i<size; i++) {
	beg = split (portrangelist[i],sep:"-",keep:FALSE);
	if (isnull(beg[1])) {
		portrangelist[i]=beg[0];
	} else {
		if (int(beg[0])>int(beg[1])) {
			tmpvar=beg[0];
			beg[0]=beg[1];
			beg[1]=tmpvar;
		}
		portrangelist[i]=beg[0] + "-" + beg[1];
	}

	for (j=i;j<size; j++) {
		prs = split (portrangelist[j],sep:"-",keep:FALSE);
		prsnext = split (portrangelist[j+1],sep:"-",keep:FALSE);
		if (isnull(prs[1]) && isnull(prsnext[1])) {
			if (prsnext[0] == (int(prs[0])+1)) {
				beg[1]=prsnext[0];
				i++;
			} else {
				break;
			}
		}
		if (isnull(prs[1]) && (!isnull(prsnext[1]))) {
			if (prsnext[0] == int(prs[0]+1)) {
				beg[1]=prsnext[1];
				i++;
			} else {
				break;
			}
		}
		if ((!isnull(prs[1])) && isnull(prsnext[1])) {
			if (prsnext[0] == int(prs[1]+1)) {
				beg[1]=prsnext[0];
				i++;
			} else {
				break;
			}
		}
		if ((!isnull(prs[1])) && (!isnull(prsnext[1]))) {
			if (prsnext[0] == int(prs[1]+1)) {
				beg[1]=prsnext[1];
				i++;
			} else {
				break;
			}
		}
	}
	if (isnull(beg[1])) {
		prlist[l]=beg[0];
	} else {
		prlist[l]=beg[0] + "-" + beg[1];
	}
	l++;
}

n_ports = 0;
oports[0]=0;

foreach pr (prlist) {
 i = 0;
 argv[i++] = "strobe";

 p = script_get_preference("Strobe timeout");
 if ( p) argv[i++] = "-t "+p;

 p = script_get_preference("Strobe number of sockets in parallel");
 if ( p) argv[i++] = "-n "+p;

 p = script_get_preference("Strobe local port to bind outgoing requests");
 if ( p) argv[i++] = "-P "+p;

 p = script_get_preference("Disable usage of getpeername");
 if ("yes" >< p) argv[i++] = "-g";

 prs = split (pr,sep:"-",keep:FALSE);

 if (isnull(prs[1])) prs[1]=prs[0];

 argv[i++] = "-b "+prs[0];

 argv[i++] = "-e "+prs[1];

 argv[i++] = ip;

 res = pread(cmd: "strobe", argv: argv, cd: 1, nice: 5);

# IP_ADDRESS:PORT:TYPE:FULL_BANNER
# 127.0.0.1    22 ssh          Secure Shell - RSA encrypted rsh
#                    -> SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1.2\n

# debug
# display(res);

	foreach line(split(res))
	{
	  v = eregmatch(string: line, pattern: '^'+esc_ip+'[ \t]*([0-9]+)[ \t]*([A-Za-z0-9])*[ \t]*(.*)$');
	  if (! isnull(v))
	  {
		port = v[1];
		if (isnull(oports[port])) {
			n_ports++;
			oports[port]=port;
			proto = "tcp";
		   scanner_add_port(proto: proto, port: port);
		}
	  }
	}

}

if (n_ports == 0) {
	log_message(port:0,proto:"tcp",data:"Host does not have any TCP port open which is specified in port range");
}

set_kb_item(name: "Host/scanned", value: TRUE);
set_kb_item(name: 'Host/scanners/strobe', value: TRUE);
if (prange == '1-65535')
  set_kb_item(name: "Host/full_scan", value: TRUE);

scanner_status(current: 65535, total: 65535);

exit (0);
