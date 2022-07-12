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

CPE = "cpe:/a:deliciousbrains:database_backup";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127037");
  script_version("2022-06-09T09:52:43+0000");
  script_tag(name:"last_modification", value:"2022-06-10 10:05:32 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-09 11:31:15 +0000 (Thu, 09 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2022-1577");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Database Backup for WordPress Plugin < 2.5.2 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-db-backup/detected");

  script_tag(name:"summary", value:"The WordPress plugin Database Backup for WordPress is prone to
  an cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows an attacker to make a logged in admin 
  change schedule backup settings via a CSRF attack. This could lead to cases where attackers can 
  send backup notification emails to themselves, which contain more details. Or disable the automatic 
  backup schedule.");

  script_tag(name:"affected", value:"WordPress Database Backup for WordPress plugin prior to
  version 2.5.2.");

  script_tag(name:"solution", value:"Update to version 2.5.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/39388900-266d-4308-88e7-d40ca6bbe346");

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

if (version_is_less(version: version, test_version: "2.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
