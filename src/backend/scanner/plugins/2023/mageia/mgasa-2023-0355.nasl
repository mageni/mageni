# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0355");
  script_cve_id("CVE-2023-6508", "CVE-2023-6509", "CVE-2023-6510", "CVE-2023-6511", "CVE-2023-6512", "CVE-2023-6702", "CVE-2023-6703", "CVE-2023-6704", "CVE-2023-6705", "CVE-2023-6706", "CVE-2023-6707", "CVE-2023-7024");
  script_tag(name:"creation_date", value:"2023-12-27 04:12:16 +0000 (Wed, 27 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-27 20:48:22 +0000 (Wed, 27 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0355)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0355");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0355.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32612");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/12/stable-channel-update-for-desktop_20.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/12/stable-channel-update-for-desktop_12.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/12/stable-channel-update-for-desktop_6.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/12/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://www.aboutchromebooks.com/news/heres-whats-in-the-now-available-google-chrome-120-release/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2023-0355 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the
120.0.6099.129 release, fixing bugs and 20 vulnerabilities, together
with 120.0.6099.109, 120.0.6099.71 and 120.0.6099.62, some of them are
listed below.
 High CVE-2023-6508: Use after free in Media Stream. Reported by Cassidy
Kim(@cassidy6564) on 2023-10-31
 High CVE-2023-6509: Use after free in Side Panel Search. Reported by
Khalil Zhani on 2023-10-21
 Medium CVE-2023-6510: Use after free in Media Capture. Reported by
[pwn2car] on 2023-09-08
 Low CVE-2023-6511: Inappropriate implementation in Autofill. Reported
by Ahmed ElMasry on 2023-09-04
 Low CVE-2023-6512: Inappropriate implementation in Web Browser UI.
Reported by Om Apip on 2023-06-24
 High CVE-2023-6702: Type Confusion in V8. Reported by Zhiyi Zhang and
Zhunki from Codesafe Team of Legendsec at Qi'anxin Group on 2023-11-10
 High CVE-2023-6703: Use after free in Blink. Reported by Cassidy
Kim(@cassidy6564) on 2023-11-14
 High CVE-2023-6704: Use after free in libavif. Reported by Fudan
University on 2023-11-23
 High CVE-2023-6705: Use after free in WebRTC. Reported by Cassidy
Kim(@cassidy6564) on 2023-11-28
 High CVE-2023-6706: Use after free in FedCM. Reported by anonymous on
2023-11-09
 Medium CVE-2023-6707: Use after free in CSS. Reported by @ginggilBesel
on 2023-11-21
 High CVE-2023-7024: Heap buffer overflow in WebRTC. Reported by Clement
Lecigne and Vlad Stolyarov of Google's Threat Analysis Group on
2023-12-19
 Google is aware that an exploit for CVE-2023-7024 exists in the wild.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~120.0.6099.129~2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~120.0.6099.129~2.mga9.tainted", rls:"MAGEIA9"))) {
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
