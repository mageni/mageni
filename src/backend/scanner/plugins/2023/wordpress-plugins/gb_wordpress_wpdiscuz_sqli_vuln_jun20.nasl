# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gvectors:wpdiscuz";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127416");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-05-02 13:30:00 +0000 (Tue, 02 May 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-06 15:15:00 +0000 (Mon, 06 Jul 2020)");

  script_cve_id("CVE-2020-13640");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress wpDiscuz Plugin < 5.3.6 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wpdiscuz/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'wpDiscuz' is prone to an
  SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows remote attackers to execute arbitrary
  SQL commands via the order parameter of a wpdLoadMoreComments request.");

  script_tag(name:"affected", value:"WordPress wpDiscuz plugin prior to version 5.3.6.");

  script_tag(name:"solution", value:"Update to version 5.3.6 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/10273");

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

if( version_is_less( version: version, test_version: "5.3.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.3.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
