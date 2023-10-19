# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dwbooster:appointment_hour_booking";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127517");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-11 12:03:12 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-15 16:34:00 +0000 (Fri, 15 Oct 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-24712");

  script_name("WordPress Appointment Hour Booking Plugin < 1.3.17 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/appointment-hour-booking/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Appointment Hour Booking' is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly sanitize values used when creating
  new calendars.");

  script_tag(name:"affected", value:"WordPress Appointment Hour Booking plugin prior to version
  1.3.17.");

  script_tag(name:"solution", value:"Update to version 1.3.17 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e677e51b-0d3f-44a5-9fcd-c159786b9926");

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

if( version_is_less( version: version, test_version: "1.3.17" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.17", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
