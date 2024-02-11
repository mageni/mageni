# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126491");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-08-30 10:25:18 +0000 (Wed, 30 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-01 14:34:00 +0000 (Fri, 01 Sep 2023)");

  script_cve_id("CVE-2023-3251", "CVE-2023-3252", "CVE-2023-3253");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Multiple Vulnerabilities (TNS-2023-29, TNS-2023-31)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-3251: A pass-back exists where an authenticated, remote attacker with administrator
  privileges could uncover stored SMTP credentials within the Nessus application.

  - CVE-2023-3252: An arbitrary file write exists where an authenticated, remote attacker with
  administrator privileges could alter logging variables to overwrite arbitrary files on the remote
  host with log data, which could lead to a denial of service condition

  - CVE-2023-3253: An improper authorization exists where an authenticated, low privileged remote
  attacker could view a list of all the users available in the application.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.5.5 and 10.6.0.");

  script_tag(name:"solution", value:"Update to version 10.5.5, 10.6.0 or later.

  Note: The installation files for version 10.5.5 can only be obtained via the Nessus
  Feed.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-29");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-31");

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

if( version_is_less_equal( version:version, test_version:"10.5.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.5.5, 10.6.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
