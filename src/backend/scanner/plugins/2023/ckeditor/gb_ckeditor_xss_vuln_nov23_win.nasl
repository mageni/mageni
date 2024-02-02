# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124477");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-20 07:40:43 +0000 (Mon, 20 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-28 19:09:00 +0000 (Tue, 28 Nov 2023)");

  script_cve_id("CVE-2023-4771");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("CKEditor <= 4.15.1 XSS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ckeditor/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"CKEditor 4 is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker could send malicious javascript code through the
  /ckeditor/samples/old/ajax.html file and retrieve an authorized user's information.");

  script_tag(name:"affected", value:"CKEditor through version 4.15.1.");

  script_tag(name:"solution", value:"No known solution is available as of 21th November, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-hxjc-9j8v-v9pr");
  script_xref(name:"URL", value:"https://www.incibe.es/en/incibe-cert/notices/aviso/cross-site-scripting-vulnerability-cksource-ckeditor");

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

if ( version_is_less_equal( version: version, test_version: "4.15.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
