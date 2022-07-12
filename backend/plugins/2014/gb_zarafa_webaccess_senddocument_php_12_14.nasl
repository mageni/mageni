###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zarafa_webaccess_senddocument_php_12_14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Zarafa WebAccess Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:zarafa:zarafa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105138");
  script_version("$Revision: 11867 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Zarafa WebAccess Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1139442");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to cause denial-of-service
conditions.");

  script_tag(name:"vuldetect", value:"Check for the existence of /senddocument.php");

  script_tag(name:"insight", value:"A flaw in Zarafa WebAccess could allow a remote unauthenticated attacker
to exhaust the disk space of /tmp. Depending on the setup /tmp might be on / (e.g. RHEL).");

  script_tag(name:"solution", value:"Delete the file '/senddocument.php' (It's neither referenced nor used anywhere)
or update to 7.2.0 beta 1 (SVN 47004).");

  script_tag(name:"summary", value:"Zarafa WebAccess is prone to a denial-of-service vulnerability.");
  script_tag(name:"affected", value:"Zarafa WebAccess >= 7.0.0 - < 7.2.0 beta 1 (SVN 47004)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-08 13:27:31 +0100 (Mon, 08 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_zarafa_webaccess_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zarafa_webaccess/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + '/senddocument.php';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "HTTP/1\.. 200" && "&attachment_id=" >< buf )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );



