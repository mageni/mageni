# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:d-link:dir-619l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170589");
  script_version("2023-10-05T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-10-05 05:05:26 +0000 (Thu, 05 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-02 10:51:15 +0000 (Mon, 02 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2023-43860", "CVE-2023-43861", "CVE-2023-43862", "CVE-2023-43863",
                "CVE-2023-43864", "CVE-2023-43865", "CVE-2023-43866", "CVE-2023-43867",
                "CVE-2023-43868", "CVE-2023-43869");

  script_name("D-Link DIR-619L <= 2.02 Multiple Buffer Overflow Vulnerabilities (Sep 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-619L devices are prone to multiple buffer overflow
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-43860: Buffer overflow via formSetWanNonLogin function

  - CVE-2023-43861: Buffer overflow via formSetWanPPPoE function

  - CVE-2023-43862: Buffer overflow via formLanguageChange function

  - CVE-2023-43863: Buffer overflow via formSetWanDhcpplus function

  - CVE-2023-43864: Buffer overflow via formSetWAN_Wizard55 function

  - CVE-2023-43865: Buffer overflow via formSetWanPPTP function

  - CVE-2023-43866: Buffer overflow via formSetWAN_Wizard7 function

  - CVE-2023-43867: Buffer overflow via formSetWanL2TP function

  - CVE-2023-43868: Buffer overflow via websGetVar function

  - CVE-2023-43868: Buffer overflow via formSetWAN_Wizard56 function");

  script_tag(name:"affected", value:"D-Link DIR-619L devices through firmware version 2.02.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that the model reached its End-of-Support Date, is no longer
  supported, and firmware development has ceased.");

  script_xref(name:"URL", value:"https://github.com/YTrick/vuln/blob/main/DIR-619L%20Buffer%20Overflow.md");
  script_xref(name:"URL", value:"https://github.com/YTrick/vuln/blob/main/DIR-619L%20Buffer%20Overflow_1.md");
  script_xref(name:"URL", value:"https://support.dlink.com/resource/products/dir-619l/");

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

# nb: Device is very old model and EOL since at least 2019
report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
security_message( port:port, data:report );
exit( 0 );
