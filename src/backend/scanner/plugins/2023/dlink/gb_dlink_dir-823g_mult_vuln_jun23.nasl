# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:d-link:dir-823g_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170506");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-05 09:32:27 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2023-26612", "CVE-2023-26613", "CVE-2023-26615", "CVE-2023-26616");

  script_name("D-Link DIR-823G <= 1.0.2B05 Multiple Vulnerabilities (July 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-823G devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-26612: Buffer overflow originating from the HostName field in SetParentsControlInfo

  - CVE-2023-26613: OS command injection via a crafted get request to EXCU_SHELL

  - CVE-2023-26615: Web page management password reset via SetMultipleActions API

  - CVE-2023-26616: Buffer overflow originating from the URL field in SetParentsControlInfo");

  script_tag(name:"affected", value:"D-Link DIR-823G devices through firmware version 1.0.2B05.");

  script_tag(name:"solution", value:"No known solution is available as of 06th July, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/726232111/VulIoT/tree/main/D-Link/DIR823G%20V1.0.2B05/HNAP1/SetMultipleActions?utm_source=substack&utm_medium=email");
  script_xref(name:"URL", value:"https://github.com/726232111/VulIoT/tree/main/D-Link/DIR823G%20V1.0.2B05/HNAP1/SetParentsControlInfo");
  script_xref(name:"URL", value:"https://github.com/726232111/VulIoT/tree/main/D-Link/DIR823G%20V1.0.2B05/excu_shell");
  script_xref(name:"URL", value:"http://www.dlink.com.cn/techsupport/ProductInfo.aspx?m=DIR-823G");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( revcomp( a:version, b:"1.0.2B05" ) <= 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
