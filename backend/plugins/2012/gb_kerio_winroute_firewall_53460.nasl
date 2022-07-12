###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_winroute_firewall_53460.nasl 11301 2018-09-10 11:24:56Z asteins $
#
# Kerio WinRoute Firewall Web Server Remote Source Code Disclosure Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103487");
  script_bugtraq_id(53460);
  script_version("$Revision: 11301 $");
  script_name("Kerio WinRoute Firewall Web Server Remote Source Code Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53460");
  script_xref(name:"URL", value:"http://www.kerio.com");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-10 13:24:56 +0200 (Mon, 10 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-05-11 13:52:12 +0200 (Fri, 11 May 2012)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Kerio_WinRoute/banner");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more details.");
  script_tag(name:"summary", value:"Kerio WinRoute Firewall is prone to a remote source-code-
disclosure vulnerability because it fails to properly sanitize user-
supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view the source code
of files in the context of the server process, this may aid in
further attacks.");

  script_tag(name:"affected", value:"Versions prior to Kerio WinRoute Firewall 6.0.0 are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("Server: Kerio WinRoute Firewall" >!< banner)exit(0);

url = '/nonauth/login.php%00.txt';

if(http_vuln_check(port:port, url:url,pattern:"require_once",extra_check:make_list("configNonauth","CORE_PATH"))) {

  security_message(port:port);
  exit(0);

}

exit(0);

