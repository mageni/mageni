###############################################################################
# OpenVAS Vulnerability Test
# $Id: mapserver_36802.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# MapServer HTTP Request Processing Integer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:umn:mapserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100317");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-26 10:02:32 +0100 (Mon, 26 Oct 2009)");
  script_bugtraq_id(36802);
  script_cve_id("CVE-2009-2281");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("MapServer HTTP Request Processing Integer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_mapserver_detect.nasl");
  script_mandatory_keys("MapServer/Installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36802");
  script_xref(name:"URL", value:"http://mapserver.gis.umn.edu/");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code.
  Successful exploits will compromise affected computers. Failed exploit attempts will result in
  a denial-of-service condition.");

  script_tag(name:"affected", value:"This issue affects MapServer 4.10.x. Other versions may be
  vulnerable as well.");

  script_tag(name:"insight", value:"This issue reportedly stems from an incomplete fix for CVE-2009-
  0840, which was discussed in BID 34306 (MapServer Multiple Security Vulnerabilities).");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"MapServer is prone to a remote integer-overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"5.4", test_version2:"5.4.2" ) ||
    version_in_range( version:vers, test_version:"5.2", test_version2:"5.2.3" ) ||
    version_in_range( version:vers, test_version:"5.0", test_version2:"5.0.3" ) ||
    version_in_range( version:vers, test_version:"4.10", test_version2:"4.10.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );