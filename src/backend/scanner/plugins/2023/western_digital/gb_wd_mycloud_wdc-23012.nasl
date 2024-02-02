# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100485");
  script_version("2023-11-09T05:05:33+0000");
  script_tag(name:"last_modification", value:"2023-11-09 05:05:33 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-23 07:22:13 +0000 (Mon, 23 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-08 15:29:00 +0000 (Thu, 08 Dec 2022)");

  script_cve_id("CVE-2022-2097", "CVE-2022-4304", "CVE-2022-4450", "CVE-2023-0215",
                "CVE-2023-0286", "CVE-2023-0464", "CVE-2023-0465", "CVE-2023-0466",
                "CVE-2023-2650", "CVE-2021-22946", "CVE-2022-27774", "CVE-2022-32221",
                "CVE-2022-43552", "CVE-2023-23916", "CVE-2021-3468", "CVE-2022-2031",
                "CVE-2022-32742", "CVE-2022-32744", "CVE-2022-32746", "CVE-2022-42898",
                "CVE-2023-22817");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.x < 5.27.157 Multiple Vulnerabilities (WDC-23012)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Updated OpenSSL to version 1.1.1n-0+deb11u5 to resolve CVE-2022-2097, CVE-2022-4304,
  CVE-2022-4450, CVE-2023-0215, CVE-2023-0286, CVE-2023-0464, CVE-2023-0465, CVE-2023-0466,
  CVE-2023-2650 that could result in inadequate encryption, app crashes, use-after-free or denial of
  service attacks

  - Updated Curl to version 7.74.0-1.3+deb11u7 to resolve CVE-2021-22946, CVE-2022-27774,
  CVE-2022-32221, CVE-2022-43552, CVE-2023-23916 that could allow an attacker to expose possibly
  sensitive data in clear text over the network, obtain sensitive information or leak credentials,
  exploit use after free vulnerability or allocate resources without limits

  - Updated Avahi to version 0.8-5+deb11u2 to resolve CVE-2021-3468 that could allow a local
  attacker to trigger an infinite loop which may result in unavailability of Avahi service

  - Updated Samba to version 4.13.13+dfsg-1~deb11u5 to resolve CVE-2022-2031, CVE-2022-32742,
  CVE-2022-32744, CVE-2022-32746 that could allow an attacker to obtain sensitive information, cause
  memory leak, or gain unauthorized access

  - Updated open-source Kerberos library to version krb5_1.18.3-6+deb11u3 to resolve CVE-2022-42898
  that may lead to remote code execution, buffer overflow, or cause a denial of service

  - CVE-2023-22817: Improved the security posture of FTP Downloads application");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud EX2
  Ultra, My Cloud EX4100, My Cloud Mirror Gen 2, My Cloud EX2100, My Cloud DL2100, My Cloud DL4100,
  My Cloud and WD Cloud with firmware prior to version 5.27.157.");

  script_tag(name:"solution", value:"Update to firmware version 5.27.157 or later.");

  script_xref(name:"URL", value:"https://os5releasenotes.mycloud.com/#5.27.157");
  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-23012-my-cloud-os5-firmware-5-27-157");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.27.157")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.27.157");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
