# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adenion:blog2social";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170276");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 17:29:25 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-23 18:03:00 +0000 (Tue, 23 Mar 2021)");

  script_cve_id("CVE-2021-24137");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Blog2Social Plugin < 6.3.1 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/blog2social/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Blog2Social' is prone to an SQL injection
  (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unvalidated input lead to SQL Injection in the Re-Share Posts
  feature, allowing authenticated users to inject arbitrary SQL commands.");

  script_tag(name:"affected", value:"WordPress Blog2Social plugin prior to version 6.3.1.");

  script_tag(name:"solution", value:"Update to version 6.3.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/9eb94e55-765b-4df5-baea-b247ef72aef3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"6.3.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.3.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
