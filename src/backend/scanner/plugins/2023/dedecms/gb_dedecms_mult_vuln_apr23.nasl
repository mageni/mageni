# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dedecms:dedecms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126283");
  script_version("2023-05-05T16:07:24+0000");
  script_tag(name:"last_modification", value:"2023-05-05 16:07:24 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-28 13:12:58 +0000 (Fri, 28 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-40886", "CVE-2023-2056", "CVE-2023-2059", "CVE-2023-2424",
                "CVE-2023-27733", "CVE-2023-30380");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("DedeCMS <= 5.7.107 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 AG");
  script_family("Web application abuses");
  script_dependencies("gb_dedecms_http_detect.nasl");
  script_mandatory_keys("dedecms/detected");

  script_tag(name:"summary", value:"DedeCMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-40886: There is a file upload function in the background, which can write malicious
  code to bypass detection and cause RCE vulnerabilities.

  - CVE-2023-2056: Function GetSystemFile in the file module_main.php can lead to code injection.

  - CVE-2023-2059: Unknown functionality in the file uploads/include/dialog/select_templets.php
  leads to path traversal: '..\filedir'.

  - CVE-2023-2424: Affected by this issue is the function UpDateMemberModCache of the file
  uploads/dede/config.php. The manipulation leads to unrestricted upload.

  - CVE-2023-27733: SQL injection via the component /dede/sys_sql_query.php

  - CVE-2023-30380: Directory traversal in DedeCMS leads attacker to traverse server
  directories.");

  script_tag(name:"affected", value:"DedeCMS version through 5.7.107.");

  script_tag(name:"solution", value:"No known solution is available as of 05th May, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/Ephemeral1y/Vulnerability/blob/master/DedeCMS/5.7.98/DedeCMS-v5.7.98-RCE.md");
  script_xref(name:"URL", value:"https://gitee.com/ashe-king/cve/blob/master/dedecms%20rce2.md");
  script_xref(name:"URL", value:"https://github.com/ATZXC-RedTeam/cve/blob/main/dedecms.md");
  script_xref(name:"URL", value:"https://gitee.com/xieqiangweb/cve/blob/master/dede/dedecms%20rce.md");
  script_xref(name:"URL", value:"https://sha999-crypto.github.io/2023/02/28/Dedecms%20background%20SQL%20injection%20vulnerability/");
  script_xref(name:"URL", value:"https://github.com/Howard512966/DedeCMS-v5.7.107-Directory-Traversal");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if (version =~ "^5") {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}
else {
  exit( 99 );
}

exit( 0 );
