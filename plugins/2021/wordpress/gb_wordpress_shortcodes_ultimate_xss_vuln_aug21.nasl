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

CPE = "cpe:/a:getshortcodes:shortcodes_ultimate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146884");
  script_version("2021-10-12T14:01:30+0000");
  script_tag(name:"last_modification", value:"2021-10-13 11:12:06 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-12 12:01:55 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-28 02:46:00 +0000 (Tue, 28 Sep 2021)");

  script_cve_id("CVE-2021-24525");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Shortcodes Ultimate Plugin < 5.10.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/shortcodes-ultimate/detected");

  script_tag(name:"summary", value:"The WordPress plugin Shortcodes Ultimate is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows users with Contributor roles to perform
  stored XSS via shortcode attributes.

  Note: the plugin is inconsistent in its handling of shortcode attributes. Some do escape, most
  don't, and there are even some attributes that are insecure by design (like [su_button]'s onclick
  attribute).");

  script_tag(name:"affected", value:"WordPress Shortcodes Ultimate plugin through version 5.10.1.");

  script_tag(name:"solution", value:"Update to version 5.10.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/7f5659bd-50c3-4725-95f4-cf88812acf1c");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/browser/shortcodes-ultimate/trunk/changelog.txt");

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

if (version_is_less(version: version, test_version: "5.10.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.10.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
