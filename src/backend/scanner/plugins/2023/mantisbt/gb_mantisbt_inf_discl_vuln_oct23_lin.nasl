# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mantisbt:mantisbt";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127646");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-29 12:36:37 +0000 (Wed, 29 Nov 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-23 13:40:00 +0000 (Mon, 23 Oct 2023)");

  script_cve_id("CVE-2023-44394");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MantisBT < 2.25.8 Information Disclosure Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MantisBT is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to insufficient access-level checks on the Wiki redirection
  page, any user can reveal private Projects' names, by accessing wiki.php with sequentially
  incremented IDs.");

  script_tag(name:"affected", value:"MantisBT prior to version 2.25.8.");

  script_tag(name:"solution", value:"Update to version 2.25.8 or later.");

  script_xref(name:"URL", value:"https://github.com/mantisbt/mantisbt/security/advisories/GHSA-v642-mh27-8j6m");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=32981");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.25.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.25.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
