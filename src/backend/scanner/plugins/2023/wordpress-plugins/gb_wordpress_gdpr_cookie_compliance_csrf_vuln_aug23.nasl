# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mooveagency:gdpr_cookie_compliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126511");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-31 09:00:48 +0000 (Thu, 31 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-01 13:27:00 +0000 (Fri, 01 Sep 2023)");

  script_cve_id("CVE-2023-4013");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GDPR Cookie Compliance Plugin < 4.12.5 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/gdpr-cookie-compliance/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'GDPR Cookie Compliance' is prone
  to a cross-site request foregery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have proper CSRF checks when managing its
  license, which could allow attackers to make logged in admins update and deactivate the plugin's
  license via CSRF attacks.");

  script_tag(name:"affected", value:"WordPress GDPR Cookie Compliance plugin prior to version
  4.12.5.");

  script_tag(name:"solution", value:"Update to version 4.12.5 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/54e4494c-a280-4d91-803d-7d55159cdbc5");

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

if( version_is_less( version: version, test_version: "4.12.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.12.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
