# OpenVAS Vulnerability Test
# $Id: sapdb_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
# Description: SAP DB detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.11929");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SAP DB detection");
# In fact, the overflow is against niserver (on port 7269)
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports(7210);

  script_tag(name:"summary", value:"SAP is listening on the remote port.

Description :
SAP/DB vserver, an ERP software, is running on the remote
port.

Please make sure that you applied the last patches, as a
buffer overflow attack has been published against it.");

  script_tag(name:"solution", value:"Make sure to be running version 7.4.03.30 or newer.

If this service is not needed, disable it or filter incoming traffic
to this port.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
##include("dump.inc");

port = 7210;
if ( ! get_port_state(port) ) exit(0);


r = hex2raw(s:	"51000000035b00000100000000000000" +
		"000004005100000000023900040b0000" +
		"d03f0000d03f00000040000070000000" +
		"4e455353555320202020202020202020" +
		"0849323335333300097064626d73727600");

s = open_sock_tcp(port);
if ( ! s ) exit(0);
send(socket: s, data: r);

r2 = recv(socket: s, length: 64);

##dump(dtitle: "SAP", ddata: r2);

if (substr(r2, 0, 6) == hex2raw(s: "40000000035c00"))
{
  log_message(port);
  register_service(port: port, proto: "sap_db_vserver");
}
