# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149702");
  script_version("2023-05-19T16:07:05+0000");
  script_tag(name:"last_modification", value:"2023-05-19 16:07:05 +0000 (Fri, 19 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-19 07:45:46 +0000 (Fri, 19 May 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:M/C:N/I:C/A:N");

  script_cve_id("CVE-2022-36326", "CVE-2022-36327", "CVE-2022-36328", "CVE-2022-29840");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.x < 5.26.202 Multiple Vulnerabilities (WDC-23006)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-36326: Uncontrolled resource consumption vulnerability that could arise by sending
  crafted requests to a service to consume a large amount of memory, eventually resulting in the
  service being stopped and restarted.

  - CVE-2022-36327: Improper limitation of a pathname to a restricted directory ('Path Traversal')
  vulnerability that could allow an attacker to write files to locations with certain critical
  filesystem types leading to remote code execution.

  - CVE-2022-36328: Improper limitation of a pathname to a restricted directory ('Path Traversal')
  vulnerability that could allow an attacker to create arbitrary shares on arbitrary directories
  and exfiltrate sensitive files, passwords, users and device configurations.

  - CVE-2022-29840: Server-side request forgery (SSRF) vulnerability that could allow a rogue
  server on the local network to modify its URL to point back to the loopback adapter.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud
  EX4100, My Cloud EX2 Ultra, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud DL4100, My Cloud
  EX2100, My Cloud and WD Cloud with firmware prior to version 5.26.202.");

  script_tag(name:"solution", value:"Update to firmware version 5.26.202 or later.");

  script_xref(name:"URL", value:"https://os5releasenotes.mycloud.com/#5.26.202");
  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-23006-my-cloud-firmware-version-5-26-202");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:wd_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.26.202")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.26.202");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
