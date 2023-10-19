# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0287");
  script_cve_id("CVE-2023-43785", "CVE-2023-43786", "CVE-2023-43787");
  script_tag(name:"creation_date", value:"2023-10-16 06:33:12 +0000 (Mon, 16 Oct 2023)");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 13:18:00 +0000 (Fri, 13 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0287)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0287");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0287.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32358");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/03/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libx11' package(s) announced via the MGASA-2023-0287 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in libX11 due to a boundary condition within
the _XkbReadKeySyms() function. This flaw allows a local user to trigger
an out-of-bounds read error and read the contents of memory on the
system. (CVE-2023-43785)

A vulnerability was found in libX11 due to an infinite loop within the
PutSubImage() function. This flaw allows a local user to consume all
available system resources and cause a denial of service condition.
(CVE-2023-43786)

A vulnerability was found in libX11 due to an integer overflow within
the XCreateImage() function. This flaw allows a local user to trigger an
integer overflow and execute arbitrary code with elevated privileges.
(CVE-2023-43787)");

  script_tag(name:"affected", value:"'libx11' package(s) on Mageia 8, Mageia 9.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64x11-devel", rpm:"lib64x11-devel~1.7.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11-xcb1", rpm:"lib64x11-xcb1~1.7.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11_6", rpm:"lib64x11_6~1.7.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11", rpm:"libx11~1.7.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-common", rpm:"libx11-common~1.7.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-devel", rpm:"libx11-devel~1.7.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-doc", rpm:"libx11-doc~1.7.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-xcb1", rpm:"libx11-xcb1~1.7.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11_6", rpm:"libx11_6~1.7.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64x11-devel", rpm:"lib64x11-devel~1.8.6~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11-xcb1", rpm:"lib64x11-xcb1~1.8.6~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11_6", rpm:"lib64x11_6~1.8.6~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11", rpm:"libx11~1.8.6~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-common", rpm:"libx11-common~1.8.6~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-devel", rpm:"libx11-devel~1.8.6~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-doc", rpm:"libx11-doc~1.8.6~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-xcb1", rpm:"libx11-xcb1~1.8.6~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11_6", rpm:"libx11_6~1.8.6~1.1.mga9", rls:"MAGEIA9"))) {
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
