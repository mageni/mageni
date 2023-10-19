# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpcode:wpcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127360");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-09 10:28:06 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-11 02:58:00 +0000 (Sat, 11 Mar 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-0328");

  script_name("WordPress WPCode - Insert Headers and Footers Plugin < 2.0.7 Improper Authorization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/insert-headers-and-footers/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WPCode - Insert Headers and Footers' is
  prone to an improper authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have adequate privilege checks in place for
  several AJAX actions, only checking the nonce.");

  script_tag(name:"affected", value:"WordPress WPCode - Insert Headers and Footers plugin prior to
  version 2.0.7.");

  script_tag(name:"solution", value:"Update to version 2.0.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/3c4318a9-a3c5-409b-a52e-edd8583c3c43");

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

if( version_is_less( version: version, test_version: "2.0.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
