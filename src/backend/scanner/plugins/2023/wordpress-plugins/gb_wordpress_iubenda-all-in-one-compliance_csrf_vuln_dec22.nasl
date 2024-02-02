# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:iubenda:iubenda-cookie-law-solution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127654");
  script_version("2023-12-14T08:20:35+0000");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-11 11:08:03 +0000 (Mon, 11 Dec 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-09 19:05:00 +0000 (Mon, 09 Jan 2023)");

  script_cve_id("CVE-2022-3911");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress iubenda All-in-one Compliance for GDPR / CCPA Cookie Consent Plugin < 3.3.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/iubenda-cookie-law-solution/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'iubenda All-in-one Compliance for
  GDPR / CCPA Cookie Consent' is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does does not have authorisation and CSRF in an AJAX
  action, and does not ensure that the options to be updated belong to the plugin as long as they
  are arrays. As a result, any authenticated users, such as subscriber can grant themselves any
  privileges, such as edit_plugins.");

  script_tag(name:"affected", value:"WordPress iubenda All-in-one Compliance for GDPR / CCPA
  Cookie Consent plugin prior to version 3.3.3.");

  script_tag(name:"solution", value:"Update to version 3.3.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/c47fdca8-74ac-48a4-9780-556927fb4e52");

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

if( version_is_less( version: version, test_version: "3.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
