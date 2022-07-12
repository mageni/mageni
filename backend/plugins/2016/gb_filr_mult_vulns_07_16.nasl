###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_filr_mult_vulns_07_16.nasl 3758 2016-07-25 17:09:24Z mime $
#
# Multiple vulnerabilities in Micro Focus (Novell) Filr
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:microfocus:filr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105827");
  script_cve_id("CVE-2016-1607", "CVE-2016-1608", "CVE-2016-1609", "CVE-2016-1610", "CVE-2016-1611");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 13825 $");

  script_name("Multiple Vulnerabilities in Micro Focus (Novell) Filr");

  script_xref(name:"URL", value:"https://www.sec-consult.com/en/Vulnerability-Lab/Advisories.htm");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities where detected in filr:

  - Cross Site Request Forgery (CSRF) - CVE-2016-1607

  - OS Command Injection - CVE-2016-1608

  - Insecure System Design

  - Persistent Cross-Site Scripting - CVE-2016-1609

  - Missing Cookie Flags

  - Authentication Bypass - CVE-2016-1610

  - Path Traversal - CVE-2016-1610

  - Insecure File Permissions - CVE-2016-1611

See the referenced advisory for further information.");

  script_tag(name:"solution", value:"Update to Filr 2 v2.0.0.465, Filr 1.2 v1.2.0.871 or newer");

  script_tag(name:"summary", value:"Filr is prone to multiple vulnerabilities");

  script_tag(name:"affected", value:"Filr 2 <= 2.0.0.421, Filr 1.2 <= 1.2.0.846");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2019-02-22 07:38:47 +0100 (Fri, 22 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-07-25 16:47:46 +0200 (Mon, 25 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_filr_version.nasl");
  script_mandatory_keys("filr/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^1\.2" )
  fix = '1.2.0.871';

else if( version =~ "^2\.0" )
  fix = '2.0.0.465';

else
  exit( 99 );

if( version_is_less( version:version, test_version:fix ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
