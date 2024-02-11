# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114194");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-11-30 14:35:37 +0000 (Thu, 30 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-11 19:28:00 +0000 (Wed, 11 Sep 2019)");

  script_cve_id("CVE-2018-9206", "CVE-2021-23369", "CVE-2021-23383", "CVE-2023-5363");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Network Monitor < 6.3.1 Multiple Vulnerabilities (TNS-2023-43)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nnm_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_network_monitor/detected");

  script_tag(name:"summary", value:"Tenable Nessus Network Monitor is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Several of the third-party components (HandlebarsJS, OpenSSL,
  and jquery-file-upload) were found to contain vulnerabilities, and updated versions have been made
  available by the providers.

  Out of caution and in line with best practice, Tenable has opted to upgrade these components to
  address the potential impact of the issues. Nessus Network Monitor 6.3.1 updates HandlebarsJS to
  version 4.7.8, OpenSSL to version 3.0.12, and jquery-file-upload to version 10.8.0.");

  script_tag(name:"affected", value:"Tenable Nessus Network Monitor prior to version 6.3.1.");

  script_tag(name:"solution", value:"Update to version 6.3.1 or later.");

  script_xref(name:"URL", value:"https://tenable.com/security/tns-2023-43");
  script_xref(name:"URL", value:"http://www.vapidlabs.com/advisory.php?v=204");
  script_xref(name:"URL", value:"https://github.com/blueimp/jQuery-File-Upload/blob/master/VULNERABILITIES.md#remote-code-execution-vulnerability-in-the-php-component");
  script_xref(name:"URL", value:"https://snyk.io/vuln/SNYK-JS-HANDLEBARS-1279029");
  script_xref(name:"URL", value:"https://snyk.io/vuln/SNYK-JS-HANDLEBARS-1056767");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20231024.txt");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"6.3.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.3.1", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
