# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webnus:modern_events_calendar_lite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127596");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-24 09:40:34 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-31 13:49:00 +0000 (Fri, 31 Mar 2023)");

  script_cve_id("CVE-2022-27848", "CVE-2023-1400");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Modern Events Calendar Lite Plugin < 6.5.2 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/modern-events-calendar-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Modern Events Calendar Lite' is prone
  to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-27848: Authenticated attackers with administrative privileges could inject arbitrary
  web scripts in pages, that will execute whenever a user accesses an injected page due to
  insufficient input sanitization and output escaping.

  - CVE-2023-1400: The plugin does not sanitise and escape some of its settings,
  which could allow high privilege users such as admin to perform stored cross-site scripting (XSS)
  attacks even when the unfiltered_html capability is disallowed.");

  script_tag(name:"affected", value:"WordPress Modern Events Calendar Lite plugin prior to version
  6.5.2");

  script_tag(name:"solution", value:"Update to version 6.5.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ef2843d0-f84d-4093-a08b-342ed0848914/");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/c7feceef-28f1-4cac-b124-4b95e3f17b07/");

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

if( version_is_less( version: version, test_version: "6.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.5.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
