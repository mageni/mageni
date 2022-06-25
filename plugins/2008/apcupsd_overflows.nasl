# OpenVAS Vulnerability Test
# $Id: apcupsd_overflows.nasl 3854 2016-08-18 13:15:25Z teissa $
# Description: apcupsd overflows
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2003 Renaud Deraison
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
#

tag_summary = "The remote apcupsd, according to its version number,
is vulnerable to a buffer overflow which could
allow an attacker to gain a root shell on this host.

*** This vulnerability was found based on the version number of the
*** remote server, so this might be a false positive";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.303176");
  script_version("$Revision: 3854 $");
  script_tag(name:"last_modification", value:"$Date: 2016-08-18 15:15:25 +0200 (Thu, 18 Aug 2016) $");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_bugtraq_id(2070, 6828, 7200);
  script_cve_id("CVE-2001-0040", "CVE-2003-0098", "CVE-2003-0099");

  
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 
  script_name("apcupsd overflows");
 

 
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
  script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
  family = "Gain a shell remotely";
  script_family(family);
  script_dependencies("find_service1.nasl", "apcnisd_detect.nasl");
  script_require_ports("Services/apcnisd", 7000);

  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

port = get_kb_item("Services/apcnisd");
if (! port) port = 7000;
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
req = raw_string(0x00, 0x06) + "status";
send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
if("APC" >< r && "MODEL" >< r)
{
  r = strstr(r, "RELEASE");
  if(ereg(pattern:"RELEASE.*: (3\.([0-7]\..*|8\.[0-5][^0-9]|10\.[0-4])|[0-2]\..*)", string:r))
       security_message(port);

}
