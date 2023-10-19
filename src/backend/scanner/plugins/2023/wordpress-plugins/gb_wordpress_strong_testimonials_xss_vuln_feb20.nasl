# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:machothemes:strong_testimonials";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127513");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-10 13:02:12 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-17 20:15:00 +0000 (Mon, 17 Feb 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-8549");

  script_name("WordPress Strong Testimonials Plugin < 2.40.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/strong-testimonials/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Strong Testimonials' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A malicious attacker is able to perform malicious actions such
  as stealing session tokens.");

  script_tag(name:"affected", value:"WordPress Strong Testimonials plugin prior to version
  2.40.1.");

  script_tag(name:"solution", value:"Update to version 2.40.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/10056");

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

if( version_is_less( version: version, test_version: "2.40.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.40.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
