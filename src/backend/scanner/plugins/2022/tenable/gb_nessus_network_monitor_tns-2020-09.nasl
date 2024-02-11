# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118435");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-12-20 14:06:37 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-17 19:53:00 +0000 (Tue, 17 Nov 2020)");

  script_cve_id("CVE-2020-5794");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Network Monitor 5.11.0, 5.11.1 and 5.12.0 (Windows) Code Execution Vulnerability (TNS-2020-09)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nnm_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_network_monitor/smb-login/detected");

  script_tag(name:"summary", value:"Tenable Nessus Network Monitor is prone to a code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability could allow an authenticated local
  attacker to execute arbitrary code by copying user-supplied files to a specially
  constructed path in a specifically named user directory.

  The attacker needs valid credentials on the Windows system to exploit this vulnerability.");

  script_tag(name:"affected", value:"Tenable Nessus Network Monitor versions 5.11.0, 5.11.1 and 5.12.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.12.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2020-09");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"5.11.0", test_version_up:"5.12.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.12.1", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
