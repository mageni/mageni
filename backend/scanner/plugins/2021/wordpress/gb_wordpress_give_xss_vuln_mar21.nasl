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

CPE = "cpe:/a:givewp:give";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146077");
  script_version("2021-06-04T03:54:14+0000");
  script_tag(name:"last_modification", value:"2021-06-04 10:13:25 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-04 03:46:13 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-24213");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GiveWP Plugin < 2.10.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/give/detected");

  script_tag(name:"summary", value:"The WordPress plugin GiveWP is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The GiveWP - Donation Plugin and Fundraising Platform WordPress
  plugin is affected by a reflected XSS vulnerability inside of the administration panel, via the
  's' GET parameter on the Donors page.");

  script_tag(name:"affected", value:"WordPress GiveWP plugin prior to version 2.10.0.");

  script_tag(name:"solution", value:"Update to version 2.10.0 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/give/#developers");
  script_xref(name:"URL", value:"https://bentl.ee/posts/cve-givewp/");

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

if (version_is_less(version: version, test_version: "2.10.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.10.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
