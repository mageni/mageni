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

CPE = "cpe:/a:use_any_font_project:use_any_font";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147792");
  script_version("2022-03-15T03:03:42+0000");
  script_tag(name:"last_modification", value:"2022-03-15 11:02:07 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-14 05:14:45 +0000 (Mon, 14 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-08 17:08:00 +0000 (Tue, 08 Mar 2022)");

  script_cve_id("CVE-2021-24977");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Use Any Font Plugin < 6.2.1 CSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/use-any-font/detected");

  script_tag(name:"summary", value:"The WordPress plugin StatCounter is prone to an arbitrary CSS
  appending vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have any authorisation checks when
  assigning a font, allowing unauthenticated users to sent arbitrary CSS which will then be
  processed by the frontend for all users. Due to the lack of sanitisation and escaping in the
  backend, it could also lead to Stored XSS issues.");

  script_tag(name:"affected", value:"WordPress Use Any Font plugin through version 6.2.0.");

  script_tag(name:"solution", value:"Update to version 6.2.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/739831e3-cdfb-4a22-9abf-6c594d7e3d75");

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

if (version_is_less(version: version, test_version: "6.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
