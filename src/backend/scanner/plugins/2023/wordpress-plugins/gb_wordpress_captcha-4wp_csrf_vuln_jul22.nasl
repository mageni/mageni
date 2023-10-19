# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpwhitesecurity:captcha_4wp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127405");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-24 07:08:03 +0000 (Mon, 24 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-05 22:27:00 +0000 (Fri, 05 Aug 2022)");

  script_cve_id("CVE-2022-2184");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress CAPTCHA 4WP Plugin < 7.1.0 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/advanced-nocaptcha-recaptcha/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'CAPTCHA 4WP' is prone to
  a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin lets user input to reach a sensitive require_once
  call in one of its admin-side templates.");

  script_tag(name:"affected", value:"WordPress CAPTCHA 4WP plugin prior to version 7.1.0.");

  script_tag(name:"solution", value:"Update to version 7.1.0 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e777784f-5ba0-4966-be27-e0a0cbbfe056");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.1.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
