# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0289");
  script_cve_id("CVE-2023-5218", "CVE-2023-5473", "CVE-2023-5474", "CVE-2023-5475", "CVE-2023-5476", "CVE-2023-5477", "CVE-2023-5478", "CVE-2023-5479", "CVE-2023-5481", "CVE-2023-5483", "CVE-2023-5484", "CVE-2023-5485", "CVE-2023-5486", "CVE-2023-5487");
  script_tag(name:"creation_date", value:"2023-10-20 04:12:17 +0000 (Fri, 20 Oct 2023)");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 02:15:00 +0000 (Fri, 13 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0289)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0289");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0289.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32381");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2023-0289 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the
118.0.5993.70 release, fixing 20 bugs and vulnerabilities.

Some of the security fixes are:

Critical CVE-2023-5218: Use after free in Site Isolation. Reported by
@18 on 2023-09-27

Medium CVE-2023-5487: Inappropriate implementation in Fullscreen.
Reported by Anonymous on 2020-03-17

Medium CVE-2023-5484: Inappropriate implementation in Navigation.
Reported by Thomas Orlita on 2023-02-11

Medium CVE-2023-5475: Inappropriate implementation in DevTools. Reported
by Axel Chong on 2023-08-30

Medium CVE-2023-5483: Inappropriate implementation in Intents. Reported
by Axel Chong on 2023-03-17

Medium CVE-2023-5481: Inappropriate implementation in Downloads.
Reported by Om Apip on 2023-06-28

Medium CVE-2023-5476: Use after free in Blink History. Reported by
Yunqin Sun on 2023-08-20

Medium CVE-2023-5474: Heap buffer overflow in PDF. Reported by [pwn2car]
on 2023-09-15

Medium CVE-2023-5479: Inappropriate implementation in Extensions API.
Reported by Axel Chong on 2023-08-09

Low CVE-2023-5485: Inappropriate implementation in Autofill. Reported by
Ahmed ElMasry on 2022-12-02

Low CVE-2023-5478: Inappropriate implementation in Autofill. Reported by
Ahmed ElMasry on 2023-08-12

Low CVE-2023-5477: Inappropriate implementation in Installer. Reported
by Bahaa Naamneh of Crosspoint Labs on 2023-08-13

Low CVE-2023-5486: Inappropriate implementation in Input. Reported by
Hafiizh on 2022-08-29

Low CVE-2023-5473: Use after free in Cast. Reported by DarkNavy on
2023-09-18

Note: Access to bug details and links may be kept restricted until a
majority of users are updated with a fix. We will also retain
restrictions if the bug exists in a third party library that other
projects similarly depend on, but haven't yet fixed.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~118.0.5993.70~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~118.0.5993.70~1.mga9.tainted", rls:"MAGEIA9"))) {
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
