# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147886");
  script_version("2022-03-31T04:09:34+0000");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-31 03:58:24 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2022-23799", "CVE-2022-23800", "CVE-2022-23801");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 4.0.0 - 4.1.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exit:

  - CVE-2022-23799: Variable tampering on JInput $_REQUEST data

  - CVE-2022-23800: Inadequate content filtering within the filter code

  - CVE-2022-23801: XSS attack vector through SVG");

  script_tag(name:"affected", value:"Joomla! version 4.0.0 through 4.1.0.");

  script_tag(name:"solution", value:"Update to version 4.1.1 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/876-20220307-core-variable-tampering-on-jinput-request-data.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/877-20220308-core-inadequate-content-filtering-within-the-filter-code.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/878-20220309-core-xss-attack-vector-through-svg.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
