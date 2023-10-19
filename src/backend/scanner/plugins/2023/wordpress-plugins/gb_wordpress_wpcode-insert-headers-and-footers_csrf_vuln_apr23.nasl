# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:wpcode:wpcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127511");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-08 14:28:06 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-04 15:30:00 +0000 (Thu, 04 May 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-1624");

  script_name("WordPress WPCode - Insert Headers and Footers Plugin < 2.0.9 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/insert-headers-and-footers/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WPCode - Insert Headers and Footers' is
  prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin has a flawed CSRF when deleting log, and does not
  ensure that the file to be deleted is inside the expected folder. This could allow attackers to
  make users with the wpcode_activate_snippets capability delete arbitrary log files on the server,
  including outside of the blog folders.");

  script_tag(name:"affected", value:"WordPress WPCode - Insert Headers and Footers plugin prior to
  version 2.0.9.");

  script_tag(name:"solution", value:"Update to version 2.0.9 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/132b70e5-4368-43b4-81f6-2d01bc09dc8f");

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

if( version_is_less( version: version, test_version: "2.0.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.9", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
