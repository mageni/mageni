# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atutor:atutor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126032");
  script_version("2023-03-31T10:08:37+0000");
  script_tag(name:"last_modification", value:"2023-03-31 10:08:37 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-29 09:50:35 +0000 (Wed, 29 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-27008");

  script_name("ATutor < 2.2.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atutor_detect.nasl");
  script_mandatory_keys("atutor/detected");

  script_tag(name:"summary", value:"Atutor is prone to an cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Reflected XSS in login.tmpl.php and login_functions.inc.php can
  be exploited in login.php via a POST request.");

  script_tag(name:"affected", value:"Atutor prior to version 2.2.4.");

  script_tag(name:"solution", value:"Update to version 2.2.4 or later.");

  script_xref(name:"URL", value:"https://plantplants213607121.wordpress.com/2023/02/16/atutor-2-2-1-cross-site-scripting-via-the-token-body-parameter/comment-page-1/?unapproved=1&moderation-hash=4856ff993af49653d7c460bea3fa6c39#comment-1");

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

if( version_is_less( version: version, test_version: "2.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit(99);
