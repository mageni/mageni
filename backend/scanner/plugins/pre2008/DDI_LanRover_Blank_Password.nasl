# OpenVAS Vulnerability Test
# $Id: DDI_LanRover_Blank_Password.nasl 13624 2019-02-13 10:02:56Z cfischer $
# Description: Shiva LanRover Blank Password
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2002 Digital Defense Incorporated
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
  script_oid("1.3.6.1.4.1.25623.1.0.10998");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("Shiva LanRover Blank Password");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2002 Digital Defense Incorporated");
  script_family("Privilege escalation");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/shiva/lanrover/detected");

  script_tag(name:"solution", value:"Telnet to this device and change the
  password for the root account via the passwd command. Please ensure any other
  accounts have strong passwords set.");

  script_tag(name:"summary", value:"The Shiva LanRover has no password set for the
  root user account.");

  script_tag(name:"impact", value:"An attacker is able to telnet to this system and
  gain access to any phone lines attached to this device. Additionally, the LanRover
  can be used as a relay point for further attacks via the telnet and rlogin functionality
  available from the administration shell.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include('telnet_func.inc');
port = 23;
if(!get_port_state(port))exit(0);

banner = get_telnet_banner(port:port);
if ( ! banner || "@ Userid:" >!< banner ) exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = telnet_negotiate(socket:soc);

  if("@ Userid:" >< r)
  {
    send(socket:soc, data:string("root\r\n"));
    r = recv(socket:soc, length:4096);

    if("Password?" >< r)
    {
      send(socket:soc, data:string("\r\n"));
      r = recv(socket:soc, length:4096);

      if ("Shiva LanRover" >< r)
      {
        security_message(port:port);
      }
    }
  }
  close(soc);
}