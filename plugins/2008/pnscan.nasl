##############################################################################
# OpenVAS Vulnerability Test
# $Id: pnscan.nasl 11665 2018-09-28 07:14:18Z cfischer $
#
# NASL wrapper around pnscan portscanner
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
  script_oid("1.3.6.1.4.1.25623.1.0.80001");
  script_version("$Revision: 11665 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 09:14:18 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-08-31 23:34:05 +0200 (Sun, 31 Aug 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("pnscan (NASL wrapper)");
  script_category(ACT_SCANNER);
  script_copyright("This script is Copyright (C) 2008 Vlatko Kosturjak");
  script_family("Port scanners");
  script_add_preference(name:"Pnscan Timeout", type:"entry", value:"");
  script_add_preference(name:"Pnscan Concurrent worker threads", type:"entry", value:"");
  script_dependencies("toolcheck.nasl", "ping_host.nasl");
  script_mandatory_keys("Tools/Present/pnscan");

  script_tag(name:"summary", value:"This plugin runs pnscan to find open ports.
  Pnscan is a lite multi-threaded port scanner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

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
 argv[i++] = "pnscan";
 argv[i++] = "-l";

 p = script_get_preference("Pnscan Timeout");
 if ( p) argv[i++] = "-t "+p;

 p = script_get_preference("Pnscan Concurrent worker threads");
 if ( p) argv[i++] = "-n "+p;

 argv[i++] = ip;
 # replace patterns like 1-65535 to 1:65535
 pr2 = ereg_replace (string:pr, pattern:"-",replace:":",icase:FALSE);
 argv[i++] = pr2;

 res = pread(cmd: "pnscan", argv: argv, cd: 1, nice: 5);

# IP_ADDRESS:PORT:TYPE:FULL_BANNER
# 127.0.0.1       :    22 : TXT : SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1.2
# 127.0.0.1       :  3306 : HEX : 40 00 00 00 0a 35 2e 30 2e 35 31 61 2d 33 75 62 75 6e 74 75 35 2e 31 00 30 00 00 00 2f 26 6f 21 50 50 22 58 00 2c a2 08 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 72 56 39 5a 39 4b 50 2d 32

	foreach line(split(res))
	{
	  v = eregmatch(string: line, pattern: '^'+esc_ip+' *: *([0-9]+) *:([^:]*): *(.*)$');
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
set_kb_item(name: 'Host/scanners/pnscan', value: TRUE);
if (pr2 == '1:65535')
  set_kb_item(name: "Host/full_scan", value: TRUE);

scanner_status(current: 65535, total: 65535);

exit (0);
