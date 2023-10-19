# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ninjateam:wp_duplicate_page";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127554");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-12 09:40:45 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 21:04:00 +0000 (Fri, 15 Jul 2022)");

  script_cve_id("CVE-2022-2093");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Duplicate Page Plugin < 1.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-duplicate-page/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Duplicate Page' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitize and escape some of its settings,
  which could allow high privilege users such as admin to perform Cross-Site Scripting attacks even
  when unfiltered_html is disallowed.");

  script_tag(name:"affected", value:"WordPress WP Duplicate Page prior to version 1.3.");

  script_tag(name:"solution", value:"Update to version 1.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/a11628e4-f47b-42d8-9c09-7536d49fce4c");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
