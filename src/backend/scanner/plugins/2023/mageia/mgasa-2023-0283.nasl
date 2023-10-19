# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0283");
  script_cve_id("CVE-2023-4761", "CVE-2023-4762", "CVE-2023-4763", "CVE-2023-4764", "CVE-2023-4863", "CVE-2023-4900", "CVE-2023-4901", "CVE-2023-4902", "CVE-2023-4903", "CVE-2023-4904", "CVE-2023-4905", "CVE-2023-4906", "CVE-2023-4907", "CVE-2023-4908", "CVE-2023-4909", "CVE-2023-5186", "CVE-2023-5187", "CVE-2023-5217");
  script_tag(name:"creation_date", value:"2023-10-10 04:12:06 +0000 (Tue, 10 Oct 2023)");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-30 04:15:00 +0000 (Sat, 30 Sep 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0283");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0283.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32317");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_27.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_21.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_15.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_12.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_11.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2023-0283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the 117.0.5938.92
release, fixing bugs and 31 vulnerabilities, together with 117.0.5938.92,
117.0.5938.88, 117.0.5938.62, 116.0.5845.187 and 116.0.5845.179.

Google is aware that an exploit for CVE-2023-5217 exists in the wild.

High CVE-2023-5217: Heap buffer overflow in vp8 encoding in libvpx.
Reported by Clement Lecigne of Google's Threat Analysis Group on
2023-09-25

High CVE-2023-5186: Use after free in Passwords. Reported by [pwn2car]
on 2023-09-05

High CVE-2023-5187: Use after free in Extensions. Reported by
Thomas Orlita on 2023-08-25

Critical CVE-2023-4863: Heap buffer overflow in WebP. Reported by Apple
Security Engineering and Architecture (SEAR) and The Citizen Lab at The
University of Toronto's Munk School on 2023-09-06

Medium CVE-2023-4900: Inappropriate implementation in Custom Tabs.
Reported by Levit Nudi from Kenya on 2023-04-06

Medium CVE-2023-4901: Inappropriate implementation in Prompts. Reported
by Kang Ali on 2023-06-29

Medium CVE-2023-4902: Inappropriate implementation in Input. Reported by
Axel Chong on 2023-06-14

Medium CVE-2023-4903: Inappropriate implementation in Custom Mobile Tabs.
Reported by Ahmed ElMasry on 2023-05-18

Medium CVE-2023-4904: Insufficient policy enforcement in Downloads.
Reported by Tudor Enache @tudorhacks on 2023-06-09

Medium CVE-2023-4905: Inappropriate implementation in Prompts. Reported
by Hafiizh on 2023-04-29

Low CVE-2023-4906: Insufficient policy enforcement in Autofill. Reported
by Ahmed ElMasry on 2023-05-30

Low CVE-2023-4907: Inappropriate implementation in Intents. Reported by
Mohit Raj (shadow2639) on 2023-07-04

Low CVE-2023-4908: Inappropriate implementation in Picture in Picture.
Reported by Axel Chong on 2023-06-06

Low CVE-2023-4909: Inappropriate implementation in Interstitials.
Reported by Axel Chong on 2023-07-09

Critical CVE-2023-4863: Heap buffer overflow in WebP

High CVE-2023-4761: Out of bounds memory access in FedCM. Reported by
DarkNavy on 2023-08-28

High CVE-2023-4762: Type Confusion in V8. Reported by anonymous on
2023-08-16

High CVE-2023-4763: Use after free in Networks. Reported by anonymous
on 2023-08-03

High CVE-2023-4764: Incorrect security UI in BFCache. Reported by Irvan
Kurniawan (sourc7) on 2023-05-20");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~117.0.5938.132~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~117.0.5938.132~1.mga9.tainted", rls:"MAGEIA9"))) {
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
