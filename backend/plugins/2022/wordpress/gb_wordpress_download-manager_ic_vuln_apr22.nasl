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

CPE = "cpe:/a:wpdownloadmanager:wordpress_download_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124061");
  script_version("2022-05-02T03:04:50+0000");
  script_tag(name:"last_modification", value:"2022-05-02 10:00:52 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2022-04-27 07:14:14 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-15 18:36:00 +0000 (Fri, 15 Apr 2022)");

  script_cve_id("CVE-2022-0828");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Download Manager Plugin < 3.2.29 Insufficient Cryptography Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/download-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin Download Manager is prone to an
  insufficient cryptography vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin uses the uniqid php function to generate the master
  key for a download, allowing an attacker to brute force the key with reasonable resources giving
  direct download access regardless of role based restrictions or password protections set for the
  download.");

  script_tag(name:"affected", value:"WordPress Download Manager plugin prior to version 3.2.29.");

  script_tag(name:"solution", value:"Update to version 3.2.29 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/7f0742ad-6fd7-4258-9e44-d42e138789bb");

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

if (version_is_less(version: version, test_version: "3.2.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
