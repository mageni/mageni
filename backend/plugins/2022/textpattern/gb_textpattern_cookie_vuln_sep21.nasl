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

CPE = "cpe:/a:textpattern:textpattern";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124096");
  script_version("2022-07-06T06:26:29+0000");
  script_tag(name:"last_modification", value:"2022-07-06 06:26:29 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-04 14:40:46 +0000 (Mon, 04 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-40642");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Textpattern CMS < 4.8.8 Cookie Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_textpattern_cms_http_detect.nasl");
  script_mandatory_keys("textpattern_cms/detected");

  script_tag(name:"summary", value:"Textpattern CMS is missing the 'Secure' flag in the cookie for
  HTTPS sessions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Textpattern CMS version 4.8.7 and prior.");

  script_tag(name:"solution", value:"Update to version 4.8.8 or later.");

  script_xref(name:"URL", value:"https://github.com/textpattern/textpattern/commit/211fab0093999f59b0b61682aa988ac7d8337aa9");

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

if (version_is_less(version: version, test_version: "4.8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
