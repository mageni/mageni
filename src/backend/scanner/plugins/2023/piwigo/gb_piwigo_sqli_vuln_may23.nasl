# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127437");
  script_version("2023-05-22T12:17:59+0000");
  script_tag(name:"last_modification", value:"2023-05-22 12:17:59 +0000 (Mon, 22 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-19 12:12:40 +0000 (Fri, 19 May 2023)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-27233");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo 11.0.x < 13.6.0 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A SQL injection via the order[0][dir] parameter at
  user_list_backend.php.");

  script_tag(name:"affected", value:"Piwigo version 11.0.x prior to 13.6.0.");

  script_tag(name:"solution", value:"Update to version 13.6.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/1872");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit(0);

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "11.0.0", test_version_up: "13.6.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.6.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
