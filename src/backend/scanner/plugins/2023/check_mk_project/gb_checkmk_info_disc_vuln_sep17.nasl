# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126507");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-10-18 13:14:26 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk < 1.2.8p26 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"During saving the number of failed logins, it could happen that
  parallel calls try to rename a non-exisiting file, which has just been renamed by a previous
  concurrent process. This causes the Check_MK GUI to fail and generate a crash report disclosing
  a variety of information, such as internal server paths and detailed user information.");

  script_tag(name:"affected", value:"Checkmk prior to version 1.2.8p26.");

  script_tag(name:"solution", value:"Update to version 1.2.8p26 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/5208");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.2.8p26" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2.8p26", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
