# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cesanta:mongoose";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126477");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-17 10:12:43 +0000 (Mon, 17 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2023-3696");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mongoose Web Server < 7.3.4 Prototype Pollution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_mongoose_web_server_http_detect.nasl");
  script_mandatory_keys("cesanta/mongoose/detected");

  script_tag(name:"summary", value:"Mongoose Web Server is prone to a prototype pollution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If an attacker has some way to control an object on the Mongo
  server through one way or another, it is possible to cause prototype pollution on any Mongoose
  client. Notably, if a poorly implemented service allows a user to control the object in
  findByIdAndUpdate and similar functions, this bug could be triggered through the $rename
  operator.");

  script_tag(name:"affected", value:"Mongoose Web Server prior to version 7.3.4.");

  script_tag(name:"solution", value:"Update to version 7.3.4 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/1eef5a72-f6ab-4f61-b31d-fc66f5b4b467/");

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

if( version_is_less( version: version, test_version: "7.3.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.3.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
