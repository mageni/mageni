# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:maxfoundry:maxbuttons";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127574");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-05 07:30:00 +0000 (Thu, 05 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-23 18:23:00 +0000 (Tue, 23 Aug 2022)");

  script_cve_id("CVE-2022-36346", "CVE-2022-38703");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress MaxButtons Plugin < 9.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/maxbuttons/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'MaxButtons' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-36346: The plugin does not have CSRF check in place when updating its settings, which
  could allow attackers to make a logged in admin change them via a cross-site request forgery
  (CSRF) attack.

  - CVE-2022-38703: The plugin does not sanitise and escape some of its settings, which could allow
  high privilege users such as admin to perform stored cross-site scripting (XSS) attacks.");

  script_tag(name:"affected", value:"WordPress MaxButtons plugin prior to version 9.3.");

  script_tag(name:"solution", value:"Update to version 9.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/c1b448e0-430a-4f47-aded-77af8d291232/");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/534c5bc0-dff4-4ee6-ad29-a04f75c7e404/");

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

if( version_is_less( version: version, test_version: "9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
