###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dienstplan_49412.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# Dienstplan Predictable Random Password Generation Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103237");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-02 13:13:57 +0200 (Fri, 02 Sep 2011)");
  script_bugtraq_id(49412);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Dienstplan Predictable Random Password Generation Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49412");
  script_xref(name:"URL", value:"http://www.thomas-gubisch.de/dienstplan.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/current/0370.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Dienstplan is prone to an insecure random password generation
vulnerability.

Successfully exploiting this issue may allow an attacker to guess
randomly generated passwords.

Versions prior to Dienstplan 2.3 are vulnerable.");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/dienstplan", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = string(dir, "/?page=login&action=about");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if("Dienstplan" >!< res) continue;
  version = eregmatch(pattern:"Dienstplan Version ([0-9.]+)", string: res);
  if(isnull(version[1])) continue;

  if(version_is_less(version:version[1], test_version:"2.3")) {
    report = report_fixed_ver( installed_version:version[1], fixed_version:"2.3" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
