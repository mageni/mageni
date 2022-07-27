# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:fabrix:mtheme-unus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112823");
  script_version("2020-09-22T08:34:04+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-09-22 09:48:49 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-07 12:44:11 +0000 (Mon, 07 Sep 2020)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WordPress Theme mTheme-Unus < 2.3 LFI Vulnerability (Version Check)");

  script_cve_id("CVE-2015-9406");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_theme_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/mtheme-unus/detected");

  script_tag(name:"summary", value:"The WordPress theme mTheme-Unus, which comes with the WP Mobile Edition plugin,
  is prone to a local file inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the theme not filtering the data
  in the GET parameter 'files' in file 'themes/mTheme-Unus/css/css.php'.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to gain access to sensitive file information.");

  script_tag(name:"affected", value:"WordPress mTheme-Unus theme before version 2.3.");

  script_tag(name:"solution", value:"Update to version 2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36733");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-mobile-edition/#developers");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133778/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"2.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.3", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
