###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tandberg_46107.nasl 13568 2019-02-11 10:22:27Z cfischer $
#
# Cisco TANDBERG C Series and E/EX Series Default Credentials Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103606");
  script_bugtraq_id(46107);
  script_cve_id("CVE-2011-0354");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13568 $");

  script_name("Cisco TANDBERG C Series and E/EX Series Default Credentials Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46107");
  script_xref(name:"URL", value:"http://www.cisco.com/en/US/products/ps11422/products_security_advisory09186a0080b69541.shtml");
  script_xref(name:"URL", value:"http://www.tandberg.com/support/video-conferencing-software-download.jsp?t=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/516126");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/436854");

  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-11-14 11:19:49 +0100 (Wed, 14 Nov 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"solution", value:"The vendor has released an advisory along with fixes. Please see the
  referenced advisory for more information.");

  script_tag(name:"summary", value:"Cisco TANDBERG C Series Endpoints and E/EX Series Personal Video
  devices are prone to a remote authentication-bypass vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain unauthorized root access to
  the affected devices. Successful exploits will result in the complete compromise of the affected device.");

  exit(0);
}

include("ssh_func.inc");

port = get_ssh_port(default:22);

sock = open_sock_tcp(port);
if(!sock)exit(0);

login = ssh_login(socket:sock, login:"root", password:"");

if(login == 0) {

  cmd = ssh_cmd(socket:sock,cmd:"ls -l /apps/bin/tandberg");
  close(sock);

  if(eregmatch(pattern:"-rwx.*root.*/apps/bin/tandberg", string:cmd)) {
    security_message(port:port);
    exit(0);
  }

}

if(sock)close(sock);

exit(0);