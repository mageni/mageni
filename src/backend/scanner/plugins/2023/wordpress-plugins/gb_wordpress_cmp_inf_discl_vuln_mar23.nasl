# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:niteothemes:cmp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127362");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-13 06:49:13 +0000 (Mon, 13 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-14 16:33:00 +0000 (Tue, 14 Mar 2023)");

  script_cve_id("CVE-2023-1263");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress CMP - Coming Soon & Maintenance Plugin < 4.1.7 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/cmp-comming-soon-maintenance/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'CMP - Coming Soon & Maintenance' is prone
  to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Attackers are able to obtain the contents of any
  non-password-protected, published post or page via cmp_get_post_detail function, even when
  maintenance mode is enabled.");

  script_tag(name:"affected", value:"WordPress CMP - Coming Soon & Maintenance prior to
  version 4.1.7.");

  script_tag(name:"solution", value:"Update to version 4.1.7 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/e01b4259-ed8d-44a4-9771-470de45b14a8");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.1.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
