###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_mult_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# IBM Domino KeyView PDF Filter Buffer Overflow Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:lotus_domino";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106112");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-04 08:56:27 +0700 (Mon, 04 Jul 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-0277", "CVE-2016-0278", "CVE-2016-0279", "CVE-2016-0301");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM Domino KeyView PDF Filter Buffer Overflow Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");

  script_tag(name:"summary", value:"IBM Domino is prone to multiple buffer overflow vulnerabilities in
KeyView PDF filter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"IBM Domino is prone to multiple heap-based buffer overflow vulnerabilities
in the KeyView PDF filter.");

  script_tag(name:"impact", value:"Remote attackers may execute arbitrary code via a crafted PDF document.");

  script_tag(name:"affected", value:"IBM Domino 8.5.x before 8.5.3 FP6 IF13 and 9.x before 9.0.1 FP6");

  script_tag(name:"solution", value:"Update to 8.5.3 FP6 IF13 or 9.0.1 FP6 or later versions.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21983292");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc"); # Used in get_highest_app_version
include("host_details.inc");

if( ! version = get_highest_app_version( cpe:CPE ) ) exit( 0 );

vers = ereg_replace(pattern: "FP", string: version, replace: ".");
vers = ereg_replace(pattern: "IF", string: vers, replace: ".");

if (version_in_range(version: vers, test_version: "8.5.0", test_version2: "8.5.3.6.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.3 FP6 IF13");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: vers, test_version: "9.0", test_version2: "9.0.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.1 FP6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
