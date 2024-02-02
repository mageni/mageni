# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cerber:wp_cerber_security%2c_anti-spam_%26_malware_scan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124452");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-30 09:09:05 +0000 (Mon, 30 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-09 19:44:00 +0000 (Mon, 09 Jan 2023)");

  script_cve_id("CVE-2022-4417");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Cerber Security, Anti-spam & Malware Scan Plugin < 9.3.3 Authorization Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-cerber/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Cerber Security, Anti-spam & Malware
  Scan' is prone to an authorization bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly block access to the REST API users
  endpoint when the blog is in a subdirectory, which could allow attackers to bypass the
  restriction in place and list users.");

  script_tag(name:"affected", value:"WordPress WP Cerber Security, Anti-spam & Malware Scan plugin
  prior to version 9.3.3.");

  script_tag(name:"solution", value:"Update to version 9.3.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/a8c6b077-ff93-4c7b-970f-3be4d7971aa5");

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

if (version_is_less(version: version, test_version: "9.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
