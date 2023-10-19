# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dwbooster:appointment_hour_booking";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127514");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-11 08:03:12 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-01 22:04:00 +0000 (Thu, 01 Dec 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-4034", "CVE-2022-4035", "CVE-2022-4036");

  script_name("WordPress Appointment Hour Booking Plugin < 1.3.73 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/appointment-hour-booking/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Appointment Hour Booking' is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-4034: It possible for unauthenticated attackers to embed untrusted input into content
  during booking creation that may be exported as a CSV file when a site's administrator exports
  booking details.

  - CVE-2022-4035: It possible for unauthenticated attackers to inject iFrames when submitting a
  booking that will execute whenever a user accesses the injected booking details page.

  - CVE-2022-4036: The plugin has an insufficiently strong hashing algorithm on the CAPTCHA secret
  that is also displayed to the user via a cookie.");

  script_tag(name:"affected", value:"WordPress Appointment Hour Booking plugin prior to version
  1.3.73.");

  script_tag(name:"solution", value:"Update to version 1.3.73 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories-continued/#CVE-2022-4034");
  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories-continued/#CVE-2022-4035");
  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories-continued/#CVE-2022-4036");

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

if( version_is_less( version: version, test_version: "1.3.73" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.73", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
