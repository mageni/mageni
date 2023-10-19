# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:activity_log_project:activity_log";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126496");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-26 09:30:48 +0000 (Tue, 26 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-26 14:44:00 +0000 (Tue, 26 Sep 2023)");

  script_cve_id("CVE-2023-4281");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Aryo Activity Log Plugin < 2.8.8 IP Spoofing Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/aryo-activity-log/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Aryo Activity Log' is prone to an IP
  spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This plugin retrieves client IP addresses from potentially
  untrusted headers, allowing an attacker to manipulate its value. This may be used to hide the
  source of malicious traffic.");

  script_tag(name:"affected", value:"WordPress Aryo Activity Log plugin prior to version 2.8.8.");

  script_tag(name:"solution", value:"Update to version 2.8.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/f5ea6c8a-6b07-4263-a1be-dd033f078d49");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.8.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
