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

CPE = "ccpe:/a:brandexponents:tatsu";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148139");
  script_version("2022-05-19T12:23:28+0000");
  script_tag(name:"last_modification", value:"2022-05-20 09:52:18 +0000 (Fri, 20 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-19 03:35:44 +0000 (Thu, 19 May 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-05 12:12:00 +0000 (Thu, 05 May 2022)");

  script_cve_id("CVE-2021-25094");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Tatsu Plugin < 3.3.12 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/tatsu/detected");

  script_tag(name:"summary", value:"The WordPress plugin Tatsu is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin add_custom_font action can be used without prior
  authentication to upload a rogue zip file which is uncompressed under the WordPress's upload
  directory. By adding a PHP shell with a filename starting with a dot '.', this can bypass
  extension control implemented in the plugin. Moreover, there is a race condition in the zip
  extraction process which makes the shell file live long enough on the filesystem to be callable
  by an attacker.");

  script_tag(name:"affected", value:"WordPress Tatsu plugin version 3.3.11 and prior.");

  script_tag(name:"solution", value:"Update to version 3.3.12 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/fb0097a0-5d7b-4e5b-97de-aacafa8fffcd");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2022/05/millions-of-attacks-target-tatsu-builder-plugin/");

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

if (version_is_less(version: version, test_version: "3.3.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
