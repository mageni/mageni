# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118411");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-11-09 12:53:13 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-28 21:31:00 +0000 (Tue, 28 Jun 2022)");

  script_cve_id("CVE-2022-32973", "CVE-2022-32974");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Agent < 10.1.4 Multiple Vulnerabilities (TNS-2022-13)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/detected");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Two separate vulnerabilities that utilize the custom Audit
  functionality were identified, reported and fixed. With the release of Nessus Agent 10.1.4,
  Tenable has mitigated the reported issues by enabling the ability to sign and verify custom
  audit files.

  - CVE-2022-32973: An authenticated attacker could create an audit file that bypasses
  PowerShell cmdlet checks and executes commands with administrator privileges.

  - CVE-2022-32974: An authenticated attacker could read arbitrary files from the underlying
  operating system of the scanner using a custom crafted compliance audit file without providing
  any valid SSH credentials.");

  script_tag(name:"affected", value:"Tenable Nessus Agent prior to version 10.1.4.");

  script_tag(name:"solution", value:"Update to version 10.1.4 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2022-13");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"10.1.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.1.4", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
