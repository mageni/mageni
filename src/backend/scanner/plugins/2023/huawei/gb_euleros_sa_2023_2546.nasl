# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2546");
  script_cve_id("CVE-2023-26551", "CVE-2023-26552", "CVE-2023-26553", "CVE-2023-26554", "CVE-2023-26555");
  script_tag(name:"creation_date", value:"2023-08-03 04:14:57 +0000 (Thu, 03 Aug 2023)");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-24 13:58:00 +0000 (Mon, 24 Apr 2023)");

  script_name("Huawei EulerOS: Security Advisory for ntp (EulerOS-SA-2023-2546)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2546");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2546");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ntp' package(s) announced via the EulerOS-SA-2023-2546 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write when adding a decimal point. An adversary may be able to attack a client ntpq process, but cannot attack ntpd.(CVE-2023-26552)

mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write in the cp<cpdec while loop. An adversary may be able to attack a client ntpq process, but cannot attack ntpd.(CVE-2023-26551)

mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write when adding a '\0' character. An adversary may be able to attack a client ntpq process, but cannot attack ntpd.(CVE-2023-26554)

mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write when copying the trailing number. An adversary may be able to attack a client ntpq process, but cannot attack ntpd.(CVE-2023-26553)

praecis_parse in ntpd/refclock_palisade.c in NTP 4.2.8p15 has an out-of-bounds write. Any attack method would be complex, e.g., with a manipulated GPS receiver.(CVE-2023-26555)");

  script_tag(name:"affected", value:"'ntp' package(s) on Huawei EulerOS Virtualization release 2.10.1.");

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

if(release == "EULEROSVIRT-2.10.1") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p14~3.h11.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
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
