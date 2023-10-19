# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:revmakx:infinitewp_client";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127521");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-16 10:03:12 +0000 (Wed, 16 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-21 17:49:00 +0000 (Mon, 21 Aug 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-2916");

  script_name("WordPress InfiniteWP Client Plugin < 1.12.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/iwp-client/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'InfiniteWP Client' is prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Attackers with subscriber-level permissions or above are able
  to extract sensitive data including configuration via the 'admin_notice' function.");

  script_tag(name:"affected", value:"WordPress InfiniteWP Client plugin prior to version 1.12.1.");

  script_tag(name:"solution", value:"Update to version 1.12.1 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/aa157c80-447f-4406-9e49-9cc6208b7b19");

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

if( version_is_less( version: version, test_version: "1.12.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.12.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
