# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118408");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-11-08 15:11:52 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 06:15:00 +0000 (Tue, 22 Mar 2022)");

  script_cve_id("CVE-2022-0778");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Agent < 8.3.3, 10.x < 10.1.3 DoS Vulnerability (TNS-2022-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/detected");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus leverages third-party software to help provide
  underlying functionality. One of the third-party components (OpenSSL) was found to
  contain a vulnerability, and an updated version has been made available by the provider.
  Nessus 8.15.4 and Nessus 10.1.2 update OpenSSL to version 1.1.1n to address the
  identified vulnerability.");

  script_tag(name:"affected", value:"Tenable Nessus Agent prior to version 8.3.3, 10.1.3.");

  script_tag(name:"solution", value:"Update to version 8.3.3, 10.1.3 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2022-07");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"8.3.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.3.3", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version =~ "^10\." && version_is_less( version:version, test_version:"10.1.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.1.3", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
