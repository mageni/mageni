# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fooplugins:foogallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126504");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-04 10:01:00 +0000 (Wed, 04 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-10 19:35:00 +0000 (Tue, 10 Oct 2023)");

  script_cve_id("CVE-2023-44233", "CVE-2023-44244");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress FooGallery Plugin < 2.3.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/foogallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'FooGallery' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2023-44233: Unauthenticated attackers are able to activate, download, and deactivate
  extensions via a forged request granted due to missing nonce validation on the
  handle_extension_action() function.

  CVE-2023-44244: Reflected cross-site scripting via the 'action' and 'extension'
  parameters.");

  script_tag(name:"affected", value:"WordPress FooGallery plugin prior to version 2.3.2.");

  script_tag(name:"solution", value:"Update to version 2.3.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/foogallery/foogallery-2244-cross-site-request-forgery");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/foogallery/foogallery-2244-reflected-cross-site-scripting");

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

if( version_is_less( version: version, test_version: "2.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
