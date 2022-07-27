# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:thimpress:learnpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147795");
  script_version("2022-03-15T03:03:42+0000");
  script_tag(name:"last_modification", value:"2022-03-15 11:02:07 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-14 05:39:32 +0000 (Mon, 14 Mar 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-08 16:39:00 +0000 (Tue, 08 Mar 2022)");

  script_cve_id("CVE-2022-0377");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress LearnPress Plugin < 4.1.5 Arbitrary Image Renaming Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/learnpress/detected");

  script_tag(name:"summary", value:"LearnPress plugin for WordPress is prone to an arbitrary image
  renaming vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Users of the plugin can upload an image as a profile avatar
  after the registration. After this process the user crops and saves the image. Then a 'POST'
  request that contains user supplied name of the image is sent to the server for renaming and
  cropping of the image. As a result of this request, the name of the user-supplied image is
  changed with a MD5 value. This process can be conducted only when type of the image is JPG or
  PNG. An attacker can use this vulnerability in order to rename an arbitrary image file. By doing
  this, they could destroy the design of the web site.");

  script_tag(name:"affected", value:"WordPress LearnPress plugin before version 4.1.5.");

  script_tag(name:"solution", value:"Update to version 4.1.5 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/0d95ada6-53e3-4a80-a395-eacd7b090f26");

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

if (version_is_less(version: version, test_version: "4.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
