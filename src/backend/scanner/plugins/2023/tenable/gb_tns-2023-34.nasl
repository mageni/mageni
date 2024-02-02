# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100964");
  script_version("2023-11-10T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-11-10 05:05:18 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-27 10:07:11 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-07 18:04:00 +0000 (Tue, 07 Nov 2023)");

  script_cve_id("CVE-2018-25050", "CVE-2021-23445", "CVE-2023-0465", "CVE-2023-0466",
                "CVE-2023-1255", "CVE-2023-2650", "CVE-2023-3446", "CVE-2023-38039",
                "CVE-2023-3817", "CVE-2023-4807", "CVE-2023-5622", "CVE-2023-5623",
                "CVE-2023-5624", "CVE-2023-32067");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Network Monitor < 6.3.0 Multiple Vulnerabilities (TNS-2023-34)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nnm_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_network_monitor/detected");

  script_tag(name:"summary", value:"Tenable Nessus Network Monitor is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Several of the third-party components (OpenSSL, curl, chosen,
  datatables) were found to contain vulnerabilities, and updated versions have been made available
  by the providers.

  Additionally, several other vulnerabilities were discovered, reported and fixed:

  - Under certain conditions, Nessus Network Monitor could allow a low privileged user to escalate
  privileges to NT AUTHORITY\SYSTEM on Windows hosts. - CVE-2023-5622

  - NNM failed to properly set ACLs on its installation directory, which could allow a low
  privileged user to run arbitrary code with SYSTEM privileges where NNM is installed to a
 non-standard location. - CVE-2023-5623

  - Under certain conditions, Nessus Network Monitor was found to not properly enforce input
  validation. This could allow an admin user to alter parameters that could potentially allow a
  blind SQL injection. - CVE-2023-5624");

  script_tag(name:"affected", value:"Tenable Nessus Network Monitor prior to version 6.3.0.");

  script_tag(name:"solution", value:"Update to version 6.3.0 or later.");

  script_xref(name:"URL", value:"https://tenable.com/security/tns-2023-34");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"6.3.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.3.0", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
