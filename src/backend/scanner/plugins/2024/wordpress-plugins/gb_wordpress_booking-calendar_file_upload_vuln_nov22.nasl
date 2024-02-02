# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdevart:booking_calendar";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126633");
  script_version("2024-01-24T05:06:24+0000");
  script_tag(name:"last_modification", value:"2024-01-24 05:06:24 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-05 17:28:11 +0100 (Fri, 05 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-14 22:07:00 +0000 (Wed, 14 Dec 2022)");

  script_cve_id("CVE-2022-3982");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Booking calendar, Appointment Booking System Plugin < 3.2.2 File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/booking-calendar/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Booking calendar, Appointment Booking
  System' is prone to a file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate uploaded files, which could allow
  unauthenticated users to upload arbitrary files, such as PHP and achieve RCE.");

  script_tag(name:"affected", value:"WordPress Booking calendar, Appointment Booking System plugin
  prior to version 3.2.2.");

  script_tag(name:"solution", value:"Update to version 3.2.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/4d91f3e1-4de9-46c1-b5ba-cc55b7726867");

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

if( version_is_less( version: version, test_version: "3.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
