# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpvivid:migration%2c_backup%2c_staging";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127602");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-26 11:15:08 +0000 (Thu, 26 Oct 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-27 18:56:00 +0000 (Fri, 27 Oct 2023)");

  script_cve_id("CVE-2023-5576");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Migration, Backup, Staging - WPvivid Plugin < 0.9.92 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wpvivid-backuprestore/detected");

  script_tag(name:"summary", value:"The WordPress plugin Migration, Backup, Staging - WPvivid is
  prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Google Drive API secrets are stored in plaintext in the
  publicly visible plugin source.");

  script_tag(name:"affected", value:"WordPress Migration, Backup, Staging - WPvivid plugin prior to
  version 0.9.92.");

  script_tag(name:"solution", value:"Update to version 0.9.92 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/4658109d-295c-4a1b-b219-ca1f4664ff1d");

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

if( version_is_less( version: version, test_version: "0.9.92" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.9.92", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
