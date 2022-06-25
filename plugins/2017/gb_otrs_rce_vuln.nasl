###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_rce_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# OTRS Remote Code Execution Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112139");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-24 08:52:38 +0100 (Fri, 24 Nov 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-16664");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker who is logged into OTRS as an agent can request special URLs
from OTRS which can lead to the execution of shell commands with the permissions of the web server user.");

  script_tag(name:"affected", value:"OTRS 5.0.x up to and including 5.0.23, OTRS 4.0.x up to and including 4.0.25 and OTRS 3.3.x up to and including 3.3.19");

  script_tag(name:"solution", value:"Upgrade to OTRS 3.3.20, 4.0.26, 5.0.24 or later.");

  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2017-07-security-update-otrs-framework/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.3.0", test_version2: "3.3.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.20");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.26");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.24");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
