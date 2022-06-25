##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ilias_mult_vuln_may18.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# ILIAS < 5.1.27, 5.2.16, 5.3.5 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112288");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-18 09:30:08 +0200 (Fri, 18 May 2018)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2018-11117", "CVE-2018-11118", "CVE-2018-11119", "CVE-2018-11120");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 5.1.27, 5.2.16, 5.3.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_detect.nasl");
  script_mandatory_keys("ilias/installed");

  script_tag(name:"summary", value:"ILIAS eLearning is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Services/Feeds/classes/class.ilExternalFeedItem.php in ILIAS has XSS via a link attribute. (CVE-2018-11117)

  - The RSS subsystem in ILIAS has XSS via a URI to Services/Feeds/classes/class.ilExternalFeedItem.php. (CVE-2018-11118)

  - ILIAS redirects a logged-in user to a third-party site via the return_to_url parameter. (CVE-2018-11119)

  - Services/COPage/classes/class.ilPCSourceCode.php in ILIAS has XSS. (CVE-2018-11120)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ILIAS 5.1.x up to 5.1.26, 5.2.x up to 5.2.15, 5.3.x up to 5.3.4");

  script_tag(name:"solution", value:"Update to version 5.1.27, 5.2.16 or 5.3.5 respectively.");

  script_xref(name:"URL", value:"https://www.ilias.de/docu/goto.php?target=st_229");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:ilias:ilias";

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "5.1.0", test_version2: "5.1.26")) {
  vuln = TRUE;
  fix = "5.1.27";
} else if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.15")) {
  vuln = TRUE;
  fix = "5.2.16";
} else if (version_in_range(version: version, test_version: "5.3.0", test_version2: "5.3.4")) {
  vuln = TRUE;
  fix = "5.3.5";
}

if (vuln) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
