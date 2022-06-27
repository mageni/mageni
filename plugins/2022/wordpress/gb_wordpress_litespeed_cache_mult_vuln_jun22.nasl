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

CPE = "cpe:/a:litespeedtech:litespeed_cache";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126048");
  script_version("2022-06-27T03:40:06+0000");
  script_tag(name:"last_modification", value:"2022-06-27 03:40:06 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-24 10:00:57 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-08 02:21:00 +0000 (Sat, 08 Jan 2022)");

  script_cve_id("CVE-2021-24963", "CVE-2021-24964");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress LiteSpeed Cache Plugin < 4.4.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/litespeed-cache/detected");

  script_tag(name:"summary", value:"The WordPress plugin LiteSpeed Cache is prone to
  multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2021-24963: The plugin does not escape the qc_res parameter before outputting it
  back in the JS code of an admin page, leading to a reflected cross-site scripting.  

  CVE-2021-24964: The plugin does not properly verify that requests are coming from QUIC.cloud
  servers, allowing attackers to make requests to certain endpoints by using a specific 
  X-Forwarded-For header value.");

  script_tag(name:"affected", value:"WordPress LiteSpeed Cache plugin before version 4.4.4.");

  script_tag(name:"solution", value:"Update to version 4.4.4 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/7f8b4275-7586-4e04-afd9-d12bdab6ba9b");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e9966b3e-2eb9-4d70-8c18-6a829b4827cc");

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

if (version_is_less(version: version, test_version: "4.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
