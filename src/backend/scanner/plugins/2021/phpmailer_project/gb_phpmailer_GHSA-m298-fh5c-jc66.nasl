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

CPE = "cpe:/a:phpmailer_project:phpmailer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145875");
  script_version("2021-05-03T09:07:49+0000");
  script_tag(name:"last_modification", value:"2021-05-03 10:25:12 +0000 (Mon, 03 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-03 09:02:47 +0000 (Mon, 03 May 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-36326");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("PHPMailer 6.1.8 < 6.4.1 Object Injection Vulnerability");

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmailer_detect.nasl");
  script_mandatory_keys("phpmailer/detected");

  script_tag(name:"summary", value:"PHPMailer contains an object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHPMailer allows object injection through Phar Deserialization via
  addAttachment with a UNC pathname.

  NOTE: this is similar to CVE-2018-19296, but arose because 6.1.8 fixed a functionality problem in
  which UNC pathnames were always considered unreadable by PHPMailer, even in safe contexts. As an
  unintended side effect, this fix eliminated the code that blocked addAttachment exploitation.");

  script_tag(name:"affected", value:"PHPMailer versions 6.1.8 through 6.4.0.");

  script_tag(name:"solution", value:"Update to version 6.4.1 or later.");

  script_xref(name:"URL", value:"https://github.com/PHPMailer/PHPMailer/security/advisories/GHSA-m298-fh5c-jc66");

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

if (version_in_range(version: version, test_version: "6.1.8", test_version2: "6.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
