# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elegantthemes:divi";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127674");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-03 19:20:00 +0000 (Wed, 03 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 06:22:00 +0000 (Fri, 29 Dec 2023)");

  script_cve_id("CVE-2023-6744");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elegant Themes Divi Theme < 4.23.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_themes_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/divi/detected");

  script_tag(name:"summary", value:"The WordPress theme Divi by Elegant Themes is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"Insufficient input sanitization and output escaping on user
  supplied custom field data.");

  script_tag(name:"impact", value:"Authenticated attackers, with contributor-level access and above
  are able to inject arbitrary web scripts in pages that will execute whenever a user accesses an
  injected page.");

  script_tag(name:"affected", value:"WordPress Divi theme by Elegant Themes prior to version
  4.23.2.");

  script_tag(name:"solution", value:"Update to version 4.23.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/999475c5-5f17-47fa-a0d0-47cb5a8a0eb4");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.23.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.23.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
