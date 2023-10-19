# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:constantcontact:creative_mail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126026");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-27 11:40:31 +0200 (Mon, 27 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-23 16:49:00 +0000 (Wed, 23 Nov 2022)");

  script_cve_id("CVE-2022-40686", "CVE-2022-40687", "CVE-2022-44740");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Creative Mail Plugin < 1.6.0 Multiple CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/creative-mail-by-constant-contact/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Creative Mail' is prone to multiple
  cross-site request forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2022-40686 / CVE-2022-40687 / CVE-2022-44740: Higher privileged users could execute unwanted
  actions under their current authentication leading to CSRF.");

  script_tag(name:"affected", value:"WordPress Creative Mail plugin prior to version 1.6.0.");

  script_tag(name:"solution", value:"Update to version 1.6.0 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/creative-mail-by-constant-contact/wordpress-creative-mail-plugin-1-5-4-cross-site-request-forgery-csrf-vulnerability?_s_id=cve");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/creative-mail-by-constant-contact/wordpress-creative-mail-easier-wordpress-woocommerce-email-marketing-plugin-1-5-4-cross-site-request-forgery-csrf-vulnerability?_s_id=cve");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/creative-mail-by-constant-contact/wordpress-creative-mail-plugin-1-5-4-multiple-cross-site-request-forgery-csrf-vulnerabilities?_s_id=cve");

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

if( version_is_less( version: version, test_version: "1.6.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
