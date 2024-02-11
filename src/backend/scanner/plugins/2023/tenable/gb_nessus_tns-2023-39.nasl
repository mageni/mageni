# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118560");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-11-23 12:46:50 +0000 (Thu, 23 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-29 18:01:00 +0000 (Wed, 29 Nov 2023)");

  script_cve_id("CVE-2023-6062");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Arbitrary File Write Vulnerability (TNS-2023-39)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to an arbitrary file write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An arbitrary file write vulnerability exists where an
  authenticated, remote attacker with administrator privileges on the Nessus application could alter
  Nessus Rules variables to overwrite arbitrary files on the remote host, which could lead to a
  denial of service condition.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.5.7.");

  script_tag(name:"solution", value:"Update to version 10.5.7 or later.

  Note: The installation files for version 10.5.7 can only be obtained via the Nessus
  Feed.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-39");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version:version, test_version:"10.5.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.5.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
