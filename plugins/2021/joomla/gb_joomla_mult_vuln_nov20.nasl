# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145121");
  script_version("2021-01-12T10:17:36+0000");
  script_tag(name:"last_modification", value:"2021-01-13 11:04:50 +0000 (Wed, 13 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-12 09:58:57 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-35610", "CVE-2020-35611", "CVE-2020-35612", "CVE-2020-35615");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 2.5.0 - 3.9.22 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - com_finder ignores access levels on autosuggest (CVE-2020-35610)

  - Disclosure of secrets in Global Configuration page (CVE-2020-35611)

  - Path traversal in mod_random_image (CVE-2020-35612)

  - CSRF in com_privacy emailexport feature (CVE-2020-35615)");

  script_tag(name:"affected", value:"Joomla! versions 2.5.0 - 3.9.22.");

  script_tag(name:"solution", value:"Update to version 3.9.23 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/828-20201101-core-com-finder-ignores-access-levels-on-autosuggest.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/829-20201102-core-disclosure-of-secrets-in-global-configuration-page.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/830-20201103-core-path-traversal-in-mod-random-image.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/833-20201106-core-csrf-in-com-privacy-emailexport-feature.html");

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

if (version_in_range(version: version, test_version: "2.5.0", test_version2: "3.9.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.23", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
