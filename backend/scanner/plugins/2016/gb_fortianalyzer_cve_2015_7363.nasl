###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortianalyzer_cve_2015_7363.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# FortiAnalyzer XSS Vulnerability
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

CPE = "cpe:/h:fortinet:fortianalyzer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106345");
  script_version("$Revision: 12338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-11 12:51:08 +0700 (Tue, 11 Oct 2016)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2015-7363");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FortiAnalyzer XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortianalyzer_version.nasl");
  script_mandatory_keys("fortianalyzer/version");

  script_tag(name:"summary", value:"FortiAnalyzer is prone to a XSS vulnerability.");

  script_tag(name:"insight", value:"A cross-site-scripting vulnerablity in FortiAnalyzer in advanced settings
page could allow an administrator to inject scripts in the add filter field.");

  script_tag(name:"impact", value:"An administrator could inject inject arbitrary web scripts.");

  script_tag(name:"affected", value:"FortiAnalyzer 5.0.x, 5.2.x");

  script_tag(name:"solution", value:"Update to FortiAnalyzer 5.4.0 and above, 5.2.3 and above or 5.0.12 and
above");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"http://fortiguard.com/advisory/fortianalyzer-and-fortimanager-stored-xss-vulnerability-in-report-filters");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.3");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.13");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
