# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126618");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-07 08:46:50 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:N");

  script_cve_id("CVE-2024-0955", "CVE-2024-0971");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Multiple Vulnerabilities (TNS-2024-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-0955: A stored XSS exists where an authenticated, remote attacker with administrator
  privileges on the Nessus application could alter Nessus proxy settings, which could
  lead to the execution of remote arbitrary scripts.

  - CVE-2024-0971: An SQL injection exists where an authenticated, low-privileged remote attacker
  could potentially alter scan DB content.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.7.0.");

  script_tag(name:"solution", value:"Update to version 10.7.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2024-01");

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

if( version_is_less( version:version, test_version:"10.7.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.7.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
