# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3081");
  script_cve_id("CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843");
  script_tag(name:"creation_date", value:"2023-11-01 04:20:26 +0000 (Wed, 01 Nov 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-01 16:47:18 +0000 (Thu, 01 Jun 2017)");

  script_name("Huawei EulerOS: Security Advisory for syslinux (EulerOS-SA-2023-3081)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.11\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3081");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3081");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'syslinux' package(s) announced via the EulerOS-SA-2023-3081 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The crc32_big function in crc32.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact via vectors involving big-endian CRC calculation.(CVE-2016-9843)

inftrees.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact by leveraging improper pointer arithmetic.(CVE-2016-9840)

The inflateMark function in inflate.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact via vectors involving left shifts of negative integers.(CVE-2016-9842)

inffast.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact by leveraging improper pointer arithmetic.(CVE-2016-9841)");

  script_tag(name:"affected", value:"'syslinux' package(s) on Huawei EulerOS Virtualization release 2.11.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROSVIRT-2.11.0") {

  if(!isnull(res = isrpmvuln(pkg:"syslinux", rpm:"syslinux~6.04~9.h2.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslinux-nonlinux", rpm:"syslinux-nonlinux~6.04~9.h2.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
