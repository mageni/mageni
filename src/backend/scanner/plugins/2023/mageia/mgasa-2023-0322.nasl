# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0322");
  script_cve_id("CVE-2023-5480", "CVE-2023-5482", "CVE-2023-5849", "CVE-2023-5850", "CVE-2023-5851", "CVE-2023-5852", "CVE-2023-5853", "CVE-2023-5854", "CVE-2023-5855", "CVE-2023-5856", "CVE-2023-5857", "CVE-2023-5858", "CVE-2023-5996", "CVE-2023-5997", "CVE-2023-6112");
  script_tag(name:"creation_date", value:"2023-11-21 04:12:14 +0000 (Tue, 21 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-21 01:01:21 +0000 (Tue, 21 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0322)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0322");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0322.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32529");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/11/stable-channel-update-for-desktop_14.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/11/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/10/stable-channel-update-for-desktop_31.html");
  script_xref(name:"URL", value:"https://www.gearrice.com/update/chrome-119-backs-up-and-finally-syncs-your-tabs/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2023-0322 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the
119.0.6045.159 release, fixing bugs and 15 vulnerabilities, together
with 119.0.6045.123 and 119.0.6045.105, some of them are listed below:

High CVE-2023-5480: Inappropriate implementation in Payments. Reported
by Vsevolod Kokorin (Slonser) of Solidlab on 2023-10-14

High CVE-2023-5482: Insufficient data validation in USB. Reported by
DarkNavy on 2023-10-13

High CVE-2023-5849: Integer overflow in USB. Reported by DarkNavy on
2023-10-13

High CVE-2023-5996: Use after free in WebAudio. Reported by Huang Xilin
of Ant Group Light-Year Security Lab via Tianfu Cup 2023 on 2023-10-30

High CVE-2023-5997: Use after free in Garbage Collection. Reported by
Anonymous on 2023-10-31

High CVE-2023-6112: Use after free in Navigation. Reported by Sergei
Glazunov of Google Project Zero on 2023-11-04

Medium CVE-2023-5850: Incorrect security UI in Downloads. Reported by
Mohit Raj (shadow2639) on 2021-12-22

Medium CVE-2023-5851: Inappropriate implementation in Downloads.
Reported by Shaheen Fazim on 2023-08-18

Medium CVE-2023-5852: Use after free in Printing. Reported by [pwn2car]
on 2023-09-10

Medium CVE-2023-5853: Incorrect security UI in Downloads. Reported by
Hafiizh on 2023-06-22

Medium CVE-2023-5854: Use after free in Profiles. Reported by Dohyun Lee
(@l33d0hyun) of SSD-Disclosure Labs & DNSLab, Korea Univ on 2023-10-01

Medium CVE-2023-5855: Use after free in Reading Mode. Reported by
ChaobinZhang on 2023-10-13

Medium CVE-2023-5856: Use after free in Side Panel. Reported by Weipeng
Jiang (@Krace) of VRI on 2023-10-17

Medium CVE-2023-5857: Inappropriate implementation in Downloads.
Reported by Will Dormann on 2023-10-18

Low CVE-2023-5858: Inappropriate implementation in WebApp Provider.
Reported by Axel Chong on 2023-06-24

Low CVE-2023-5859: Incorrect security UI in Picture In Picture. Reported
by Junsung Lee on 2023-09-13");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~119.0.6045.159~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~119.0.6045.159~1.mga9.tainted", rls:"MAGEIA9"))) {
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
