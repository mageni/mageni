###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_50639.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Apache HTTP Server 'ap_pregsub()' Function Local Denial of Service Vulnerability
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103333");
  script_bugtraq_id(50639);
  script_cve_id("CVE-2011-4415");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-15 12:33:51 +0100 (Tue, 15 Nov 2011)");
  script_version("$Revision: 11997 $");
  script_name("Apache HTTP Server 'ap_pregsub()' Function Local Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50639");
  script_xref(name:"URL", value:"http://httpd.apache.org/");
  script_xref(name:"URL", value:"http://www.halfdog.net/Security/2011/ApacheModSetEnvIfIntegerOverflow/");
  script_xref(name:"URL", value:"http://www.gossamer-threads.com/lists/apache/dev/403775");

  script_tag(name:"affected", value:"Apache HTTP Server 2.0.x through 2.0.64 and 2.2.x through 2.2.21 are
  vulnerable. Other versions may also be affected.");
  script_tag(name:"summary", value:"Apache HTTP Server is prone to a local denial-of-service
  vulnerability because of a NULL-pointer dereference error or a
  memory exhaustion.");
  script_tag(name:"impact", value:"Local attackers can exploit this issue to trigger a NULL-pointer
  dereference or memory exhaustion, and cause a server crash, denying
  service to legitimate users.

  Note: To trigger this issue, 'mod_setenvif' must be enabled and the
        attacker should be able to place a malicious '.htaccess' file on
        the affected webserver.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"2.0", test_version2:"2.0.64" ) ||
    version_in_range( version:vers, test_version:"2.2", test_version2:"2.2.21" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );