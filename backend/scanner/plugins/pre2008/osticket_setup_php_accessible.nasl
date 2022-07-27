###############################################################################
# OpenVAS Vulnerability Test
# $Id: osticket_setup_php_accessible.nasl 10829 2018-08-08 09:06:21Z cfischer $
#
# osTicket setup.php Accessibility
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
###############################################################################

CPE = "cpe:/a:osticket:osticket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13647");
  script_version("$Revision: 10829 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 11:06:21 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("osTicket setup.php Accessibility");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("osticket_detect.nasl");
  script_mandatory_keys("osticket/installed");

  script_tag(name:"solution", value:"Remove both setup.php and gpcvar.php and ensure permissions
  on config.php are 644.");

  script_tag(name:"summary", value:"The target is running at least one instance of an improperly secured
  installation of osTicket and allows access to setup.php.");

  script_tag(name:"impact", value:"Since that script does not require authenticated access, it is possible
  for an attacker to modify osTicket's configuration using a specially crafted call to setup.php to perform
  the INSTALL actions.");

  script_tag(name:"insight", value:"For example, if config.php is writable, an attacker could change the
  database used to store ticket information, even redirecting it to another site. Alternatively, regardless
  of whether config.php is writable, an attacker could cause the loss of all ticket information by
  reinitializing the database given knowledge of its existing configuration (gained, say, from reading config.php).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/setup.php";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );
if( isnull( res ) ) exit( 0 );

if( egrep( pattern:"title>osTicket Install", string:res, icase:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );