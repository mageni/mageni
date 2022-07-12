###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_egroupware_2014_mult_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# EGroupware Multiple CSRF and Remote Code Execution Vulnerabilities
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:egroupware:egroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108066");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2014-2987", "CVE-2014-2988");
  script_bugtraq_id(67303, 67409);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-01 09:00:00 +0100 (Wed, 01 Feb 2017)");
  script_name("EGroupware Multiple CSRF and Remote Code Execution Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_egroupware_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("egroupware/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67303");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67409");
  script_xref(name:"URL", value:"http://www.egroupware.org/");

  script_tag(name:"summary", value:"EGroupware is prone to multiple CSRF and remote PHP code-execution vulnerabilities.");

  script_tag(name:"impact", value:"Successfully exploiting these issues will allow attackers to execute arbitrary
  code within the context of the application.");

  script_tag(name:"affected", value:"EGroupware Enterprise Line (EPL) before 11.1.20140505, EGroupware Community Edition
  before 1.8.007.20140506, and EGroupware before 14.1 beta.");

  script_tag(name:"solution", value:"Upgrade to:

  - EGroupware Enterprise Line (EPL) 11.1.20140505 or later

  - EGroupware Community Edition 1.8.007.20140506 or later

  - EGroupware 14.1 beta or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # The version exposed by the application is less detailed

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

# Version is only exposed as 1.8.007 without the date
if( version_is_less( version:vers, test_version:"1.8.007" ) ) {
  vuln = TRUE;
  fix = "1.8.007.20140506";
}

# CVE says the vulnerable EPL version is 1.1.20140505 but the "real" EPL versions are 9.2 - 11.1
if( version_in_range( version:vers, test_version:"9", test_version2:"11.1.20140416" ) ) {
  vuln = TRUE;
  fix = "11.1.20140505";
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );