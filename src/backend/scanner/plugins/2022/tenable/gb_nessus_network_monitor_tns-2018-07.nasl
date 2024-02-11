# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118432");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-12-20 14:06:37 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2017-3738", "CVE-2018-0733", "CVE-2018-0739");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Network Monitor < 5.5.0 Multiple Vulnerabilities (TNS-2018-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nnm_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_network_monitor/detected");

  script_tag(name:"summary", value:"Tenable Nessus Network Monitor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"One of the third-party components (OpenSSL) were found to
  contain vulnerabilities, and updated versions have been made available by the providers.

  Nessus Network Monitor 5.5.0 updates OpenSSL to version 1.0.2o to address the identified
  vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus Network Monitor prior to version 5.5.0.");

  script_tag(name:"solution", value:"Update to version 5.5.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2018-07");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"5.5.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.5.0", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
