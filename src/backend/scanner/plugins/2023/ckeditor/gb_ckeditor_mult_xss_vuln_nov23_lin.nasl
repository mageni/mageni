# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124478");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-11-20 07:40:43 +0000 (Mon, 20 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-28 19:09:00 +0000 (Tue, 28 Nov 2023)");

  script_cve_id("CVE-2023-4771", "CVE-2024-24815", "CVE-2024-24816");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CKEditor < 4.24.0-lts Multiple XSS Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ckeditor/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"CKEditor 4 is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-4771: An attacker could send malicious javascript code through the
  /ckeditor/samples/old/ajax.html file and retrieve an authorized user's information.

  - CVE-2024-24815: An attacker could inject malformed HTML content bypassing Advanced Content
  Filtering mechanism, which could result in executing JavaScript code. This could allow to abuse
  faulty CDATA content detection and use it to prepare an intentional attack on the editor.

  - CVE-2024-24816: An attacker could execute JavaScript code by abusing the misconfigured preview
  feature through the samples used in a production mode.");

  script_tag(name:"affected", value:"CKEditor prior to version 4.24.0-lts.");

  script_tag(name:"solution", value:"Update to version 4.24.0-lts or later.");

  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-wh5w-82f3-wrxh");
  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-fq6h-4g8v-qqvm");
  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-mw2c-vx6j-mg76");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if ( !port = get_app_port( cpe: CPE ) )
  exit( 0 );

if ( !infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "4.24.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.24.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
