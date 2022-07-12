###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_coder_rce_07_16.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Drupal Coder Remote Code Execution
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105818");
  script_version("$Revision: 12313 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Drupal Coder Remote Code Execution");

  script_tag(name:"vuldetect", value:"Check for known error message from affected modules");
  script_tag(name:"insight", value:"The Coder module checks your Drupal code against coding standards and other best practices. It can also fix coding standard violations and perform basic upgrades on modules. The module doesn't sufficiently validate user inputs in a script file that has the php extension. A malicious unauthenticated user can make requests directly to this file to execute arbitrary php code.");
  script_tag(name:"summary", value:"The remote Drupal installation is prone to a remote code execution vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Install the latest version:");

  script_xref(name:"URL", value:"https://www.drupal.org/node/2765575");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-20 12:15:23 +0200 (Wed, 20 Jul 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("drupal/installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/sites/all/modules/coder/coder_upgrade/scripts/coder_upgrade.run.php';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

# Patched version has the following code at the beginning of the file
#
# if (!script_is_cli()) {
#    // Without proper web server configuration, this script can be invoked from a
#    // browser and is vulnerable to misuse.
#    return;
#
# If we see the "file parameter is not set/No path to parameter file" message, file is not patched and vulnerable

if( "file parameter is not set" >< buf || "No path to parameter file" >< buf )
{
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
