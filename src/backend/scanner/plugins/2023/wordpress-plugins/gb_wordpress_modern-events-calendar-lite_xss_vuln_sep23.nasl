# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webnus:modern_events_calendar_lite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127595");
  script_version("2023-10-27T16:11:33+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:33 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-24 09:30:34 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-26 14:55:00 +0000 (Thu, 26 Oct 2023)");

  script_cve_id("CVE-2023-4021");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Modern Events Calendar Lite Plugin < 7.1.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/modern-events-calendar-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Modern Events Calendar Lite' is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Authenticated attackers are able to inject arbitrary web
  scripts in pages that will execute whenever a user accesses an injected page due to insufficient
  input sanitization and output escaping.");

  script_tag(name:"affected", value:"WordPress Modern Events Calendar Lite plugin prior to version
  7.1.0.");

  script_tag(name:"solution", value:"Update to version 7.1.0 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/f213fb42-5bab-4017-80ea-ce6543031af2");

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

if( version_is_less( version: version, test_version: "7.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.1.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
