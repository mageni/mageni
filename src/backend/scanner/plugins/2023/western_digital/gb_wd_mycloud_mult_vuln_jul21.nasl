# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:wdc:my_cloud_pr4100_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170508");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-05 15:35:29 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2021-36224", "CVE-2021-36225", "CVE-2021-36226");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud PR4100 < 5.02.104 Multiple Vulnerabilities (July 2021)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Western Digital My Cloud PR4100 devices are prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-36224: Hard-coded user credentials

  - CVE-2021-36225: Firmware upgrade can be initiated by low privilege user.

  - CVE-2021-36226: No cryptographic verification of firmware upgrades");

  script_tag(name:"affected", value:"Western Digital My Cloud PR4100 with firmware prior to version
  5.02.104.");

  script_tag(name:"solution", value:"Update to firmware version 5.02.104 or later.");

  script_xref(name:"URL", value:"https://github.com/pedrib/PoC/blob/master/advisories/Pwn2Own/Tokyo_2020/weekend_destroyer/weekend_destroyer.md");
  script_xref(name:"URL", value:"https://krebsonsecurity.com/2021/07/another-0-day-looms-for-many-western-digital-users/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE)) # nb: No need for a version regex here, as all versions < OS 5 were affected, and test version is only the first release for OS 5
  exit(0);

if (version_is_less(version: version, test_version: "5.02.104")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.02.104");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
