###############################################################################
# OpenVAS Vulnerability Test
# $Id: TLD_wildcard.nasl 9971 2018-05-26 12:04:55Z cfischer $
#
# Exclude toplevel domain wildcard host
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 by Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# Known top level domain wildcards, from
# http://www.imperialviolet.org/dnsfix.html
#
# .COM and .NET	64.94.110.11 (and possibly others in AS30060)
# .NU	64.55.105.9 212.181.91.6
# .TK	195.20.32.83 195.20.32.86
# .CC	206.253.214.102
# .MP	202.128.12.163
# .AC	194.205.62.122
# .CC	194.205.62.122 (206.253.214.102 also reported, but cannot confirm)
# .CX	219.88.106.80
# .MUSEUM	195.7.77.20
# .PH	203.119.4.6
# .SH	194.205.62.62
# .TM	194.205.62.42 (194.205.62.62 also reported, but cannot confirm)
# .WS	216.35.187.246
#
####
#
# I also found that:
# .PW redirects to wfb.dnsvr.com = 216.98.141.250 or 65.125.231.178
# .TD   146.101.245.154
#
# .IO	194.205.62.102
# .TK	217.115.203.20	62.129.131.34
# .TD	www.nic.td.	62.23.61.4
# .MP	202.128.12.162 (new redirection?)
# .PW	 69.20.61.189  (new redirection?)
# .CX	203.119.12.43  (new redirection?)

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11840");
  script_version("$Revision: 9971 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-26 14:04:55 +0200 (Sat, 26 May 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Exclude toplevel domain wildcard host");
  script_category(ACT_SCANNER);
  script_copyright("This script is Copyright (C) 2003 by Michel Arboi");
  script_family("Port scanners");

  script_tag(name:"summary", value:"The host you were trying to scan is blacklisted: its address is known to
  be returned by a wildcard on some top level domains, or it's the openvas.org web server.

  You probably mistyped its name.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

excluded["64.94.110.11"] = 1;
excluded["64.55.105.9"] = 1;
excluded["212.181.91.6"] = 1;
excluded["195.20.32.83"] = 1;
excluded["195.20.32.86"] = 1;
excluded["206.253.214.102"] = 1;
excluded["202.128.12.163"] = 1;
excluded["194.205.62.122"] = 1;
excluded["219.88.106.80"] = 1;
excluded["195.7.77.20"] = 1;
excluded["203.119.4.6"] = 1;
excluded["194.205.62.62"] = 1;
excluded["194.205.62.42"] = 1;
excluded["216.35.187.246"] = 1;
#
excluded["216.98.141.250"] = 1;
excluded["65.125.231.178"] = 1;
excluded["146.101.245.154"] = 1;
#
excluded["194.205.62.102"] = 1;
excluded["202.128.12.162"] = 1;
excluded["217.115.203.20"] = 1;
excluded["62.129.131.34"]  = 1;
excluded["62.23.61.4"] = 1;
excluded["69.20.61.189"] = 1;
excluded["203.119.12.43"] = 1;
excluded["206.241.31.20"] = 1;
excluded["206.241.31.21"] = 1;
excluded["206.241.31.22"] = 1;
excluded["206.241.31.23"] = 1;
excluded["206.241.31.24"] = 1;
excluded["206.241.31.25"] = 1;
excluded["206.241.31.26"] = 1;
excluded["206.241.31.27"] = 1;
excluded["206.241.31.28"] = 1;
excluded["66.240.11.100"] = 1;
excluded["66.240.11.101"] = 1;
excluded["66.240.11.102"] = 1;
excluded["66.240.11.103"] = 1;
excluded["66.240.11.104"] = 1;
excluded["66.240.11.105"] = 1;
excluded["66.240.11.106"] = 1;
excluded["66.240.11.107"] = 1;
excluded["66.240.11.108"] = 1;
excluded["66.240.11.109"] = 1;
excluded["66.240.11.110"] = 1;
excluded["63.105.37.100"] = 1;
excluded["63.105.37.101"] = 1;
excluded["63.105.37.102"] = 1;
excluded["63.105.37.103"] = 1;
excluded["63.105.37.104"] = 1;
excluded["63.105.37.105"] = 1;
excluded["63.105.37.106"] = 1;
excluded["63.105.37.107"] = 1;
excluded["63.105.37.108"] = 1;
excluded["63.105.37.109"] = 1;
excluded["63.105.37.110"] = 1;

target = get_host_ip();

if (excluded[target])
{
  ##display(target, " is in IP blacklist\n");
  log_message(port:0);
  set_kb_item(name:"Host/dead", value:TRUE);
  exit(0);
}

exit(0);
# We do not test if Verisign "snubby mail rejector" is running on the
# machine, as it may be used elsewhere

soc = open_sock_tcp(25);
if (!soc) exit(0);
r = recv(socket: soc, length: 256);
if (r =~ '^220 +.*Snubby Mail Rejector')
{
  ##display(target, " looks like Verisign snubby mail server\n");
  log_message(port:0);
  set_kb_item(name:"Host/dead", value:TRUE);
}

close(soc);
