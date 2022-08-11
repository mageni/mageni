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
  script_oid("1.3.6.1.4.1.25623.1.0.147875");
  script_version("2022-03-31T04:09:34+0000");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-30 08:10:21 +0000 (Wed, 30 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2022-23793", "CVE-2022-23794", "CVE-2022-23797");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 3.0.0 - 3.10.6, 4.0.0 - 4.1.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exit:

  - CVE-2022-23793: Zip Slip within the Tar extractor

  - CVE-2022-23794: Path disclosure within filesystem error messages

  - CVE-2022-23797: Inadequate filtering on the selected Ids");

  script_tag(name:"affected", value:"Joomla! version 3.0.0 through 3.10.6 and 4.0.0 through
  4.1.0.");

  script_tag(name:"solution", value:"Update to version 3.10.7, 4.1.1 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/870-20220301-core-zip-slip-within-the-tar-extractor.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/871-20220302-core-path-disclosure-within-filesystem-error-messages.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/874-20220305-core-inadequate-filtering-on-the-selected-ids.html");
  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2022-05");

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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
