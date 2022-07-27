###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpipam_xss_vuln.nasl 9116 2018-03-16 13:04:55Z cfischer $
#
# phpIPAM < 1.2 Multiple XSS Vulnerabilities
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:phpipam:phpipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108433");
  script_version("$Revision: 9116 $");
  script_cve_id("CVE-2015-6529");
  script_tag(name:"last_modification", value:"$Date: 2018-03-16 14:04:55 +0100 (Fri, 16 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-16 13:46:59 +0100 (Fri, 16 Mar 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("phpIPAM < 1.2 Multiple XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ipam_detect.nasl");
  script_mandatory_keys("phpipam/installed");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks the version.");

  script_tag(name:"insight", value:"The vulnerabilities exist due to insufficient filtration of user-supplied
  data passed via the (1) section parameter to site/error.php or (2) ip parameter to site/tools/searchResults.php.");

  script_tag(name:"impact", value:"An attacker could execute arbitrary HTML and script code in a browser in the
  context of the vulnerable website.");

  script_tag(name:"affected", value:"phpIPAM 1.1.010 and prior.");

  script_tag(name:"solution", value:"Update to phpIPAM 1.2 or later, see http://phpipam.net for more information.");

  script_xref(name:"URL", value:"https://phpipam.net/documents/changelog/");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/133055/phpipam-1.1.010-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536188/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.2 or later.");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
