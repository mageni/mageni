# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:accesspressthemes:wp_popup_banners";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126506");
  script_version("2024-01-22T05:07:31+0000");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-10-12 09:29:45 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-28 16:13:00 +0000 (Tue, 28 Mar 2023)");

  script_cve_id("CVE-2023-1471", "CVE-2023-28661");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WordPress WP Popup Banners Plugin <= 1.2.5 Multiple SQLi Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-popup-banners/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Popup Banners' is prone to multiple
  SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Following vulnerabilities exist:

  - CVE-2023-1471: Attackers are abke to append additional SQL queries into already existing
  queries due to insufficient escaping on the user supplied parameter and lack of sufficient
  preparation on the existing SQL query.

  - CVE-2023-28661: The plugin does not properly sanitise and escape the value parameter before
  using it in a SQL statement via the get_popup_data AJAX action, leading to a SQL injection
  exploitable by any authenticated users, such as subscriber.");

  script_tag(name:"affected", value:"WordPress WP Popup Banners version 1.2.5 and prior.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/8281cb20-73d3-4ab5-910e-d353b2a5cbd8");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/c3f6770e-de15-41c2-843b-d0ae55ad6418/");

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

if (version_is_less_equal(version: version, test_version: "1.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
