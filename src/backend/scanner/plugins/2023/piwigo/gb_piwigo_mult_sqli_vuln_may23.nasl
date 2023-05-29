# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127441");
  script_version("2023-05-25T09:08:46+0000");
  script_tag(name:"last_modification", value:"2023-05-25 09:08:46 +0000 (Thu, 25 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-24 11:12:40 +0000 (Wed, 24 May 2023)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-33361", "CVE-2023-33362");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo < 13.7.0 Multiple SQLi Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to multiple SQL injection (SQLi)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2023-33361: SQL injection (SQLi) via /admin/permalinks.php

  CVE-2023-33362: SQL injection (SQLi) via /admin/profile.php");

  script_tag(name:"affected", value:"Piwigo prior to version 13.7.0.");

  script_tag(name:"solution", value:"Update to version 13.7.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/1910");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/1911");

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

if( version_is_less( version: version, test_version: "13.7.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.7.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
