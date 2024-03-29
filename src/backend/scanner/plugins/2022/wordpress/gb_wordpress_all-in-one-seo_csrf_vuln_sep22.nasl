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

CPE = "cpe:/a:semperplugins:all-in-one-seo-pack";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127182");
  script_version("2022-09-12T11:20:12+0000");
  script_tag(name:"last_modification", value:"2022-09-12 11:20:12 +0000 (Mon, 12 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-12 09:51:57 +0000 (Mon, 12 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-38093");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress All in One SEO Pack Plugin < 4.2.4 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-in-one-seo-pack/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'All in One SEO Pack' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"insight", value:"The plugin does not, or can not, sufficiently verify whether a
  well-formed, valid, consistent request was intentionally provided by the user who submitted the
  request.");

  script_tag(name:"affected", value:"WordPress All in One SEO Pack plugin prior to version 4.2.4.");

  script_tag(name:"solution", value:"Update to version 4.2.4 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/all-in-one-seo-pack/wordpress-all-in-one-seo-plugin-4-2-3-1-multiple-cross-site-request-forgery-csrf-vulnerabilities/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: FALSE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.4", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
