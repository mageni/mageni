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

CPE = "cpe:/a:enviragallery:photo_gallery";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127236");
  script_version("2022-11-02T10:12:00+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:12:00 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-01 06:02:06 +0000 (Tue, 01 Nov 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-2190");

  script_name("WordPress Envira Photo Gallery Lite Plugin < 1.8.4.7 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/envira-gallery-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Envira Photo Gallery Lite' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not escape the $_SERVER['REQUEST_URI']
  parameter before outputting it back in an attribute, which could lead to Reflected Cross-Site
  Scripting in old web browsers.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  inject arbitrary HTML and JavaScript into the site or gain privileged access.");

  script_tag(name:"affected", value:"WordPress Envira Photo Gallery Lite plugin prior to version
  1.8.4.7.");

  script_tag(name:"solution", value:"Update to version 1.8.4.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/1af4beb6-ba16-429b-acf2-43f9594f5ace");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.8.4.7")) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.4.7", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
