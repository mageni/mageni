###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpipam_mult_vuln.nasl 13504 2019-02-06 13:31:35Z jschulte $
#
# phpIPAM < 1.4 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112474");
  script_version("$Revision: 13504 $");
  script_cve_id("CVE-2018-1000860", "CVE-2018-1000869", "CVE-2018-1000870", "CVE-2019-1000010");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 14:31:35 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-02 13:50:12 +0100 (Wed, 02 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpIPAM < 1.4 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ipam_detect.nasl");
  script_mandatory_keys("phpipam/installed");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Multiple cross-site scripting vulnerabilities. (CVE-2018-1000860, CVE-2018-1000870, CVE-2019-1000010)

  - Blind SQL injection vulnerability. (CVE-2018-1000869)");

  script_tag(name:"affected", value:"phpIPAM through version 1.3.2.");

  script_tag(name:"solution", value:"Update to phpIPAM 1.4 or later.");

  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/2338");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/2326");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/2344");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:phpipam:phpipam";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
