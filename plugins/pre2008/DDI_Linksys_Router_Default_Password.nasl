# OpenVAS Vulnerability Test
# $Id: DDI_Linksys_Router_Default_Password.nasl 12821 2018-12-18 12:37:20Z cfischer $
# Description: Linksys Router Default Password
#
# Authors:
# Forrest Rae <forrest.rae@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.10999");
  script_version("$Revision: 12821 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 13:37:20 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("Linksys Router Default Password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Please assign the web administration
  console a difficult to guess password.");

  script_tag(name:"summary", value:"This Linksys Router has the default password
  set for the web administration console.");

  script_tag(name:"impact", value:"This console provides read/write access to the
  router's configuration. An attacker could take advantage of this to reconfigure the
  router and possibly re-route traffic.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

# HTTP auth = ":admin"
# req = string("GET / HTTP/1.0\r\nAuthorization: Basic OmFkbWlu\r\n\r\n");

# HTTP auth = "admin:admin"
req = string("GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n");

# nb: Both work, second is used to be RFC compliant.

buf = http_send_recv(port:port, data:req);

if( "Status.htm" >< buf && "DHCP.htm" >< buf && "Log.htm" >< buf && "Security.htm" >< buf ||
    ( "next_file=Setup.htm" >< buf && "Checking JavaScript Support" >< buf ) ) { #WAG120N
  security_message(port:port);
}
