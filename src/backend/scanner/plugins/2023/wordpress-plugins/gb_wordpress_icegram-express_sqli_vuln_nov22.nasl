# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icegram:email_subscribers_%26_newsletters";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127593");
  script_version("2023-10-24T14:40:27+0000");
  script_tag(name:"last_modification", value:"2023-10-24 14:40:27 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-23 11:10:39 +0000 (Mon, 23 Oct 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-14 22:00:00 +0000 (Wed, 14 Dec 2022)");

  script_cve_id("CVE-2022-3981");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Icegram Express Plugin < 5.5.1 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/email-subscribers/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Icegram Express' is prone to an
  SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly sanitise and escape a parameter
  before using it in a SQL statement, leading to a SQL injection exploitable by any authenticated
  users, such as subscriber.");

  script_tag(name:"affected", value:"WordPress Icegram Express plugin prior to version 5.5.1.");

  script_tag(name:"solution", value:"Update to version 5.5.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/78054d08-0227-426c-903d-d146e0919028/");

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

if( version_is_less( version: version, test_version: "5.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.5.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
