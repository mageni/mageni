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

CPE = "cpe:/a:cookieinformation:wp-gdpr-compliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147921");
  script_version("2022-04-05T08:49:18+0000");
  script_tag(name:"last_modification", value:"2022-04-05 10:21:53 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-05 03:33:40 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-21 05:17:00 +0000 (Mon, 21 Mar 2022)");

  script_cve_id("CVE-2022-0147");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Cookie Information - Free GDPR Consent Solution Plugin < 2.0.8 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-gdpr-compliance/detected");

  script_tag(name:"summary", value:"The WordPress plugin Cookie Information - Free GDPR Consent
  Solution is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not escape user data before outputting it back
  in attributes in the admin dashboard, leading to a reflected XSS issue.");

  script_tag(name:"affected", value:"WordPressCookie Information - Free GDPR Consent Solution
  plugin version 2.0.7 and prior.");

  script_tag(name:"solution", value:"Update to version 2.0.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/2c735365-69c0-4652-b48e-c4a192dfe0d1");

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

if (version_is_less(version: version, test_version: "2.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
