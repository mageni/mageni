# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0292");
  script_cve_id("CVE-2023-43788", "CVE-2023-43789");
  script_tag(name:"creation_date", value:"2023-10-20 11:39:36 +0000 (Fri, 20 Oct 2023)");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-17 18:05:00 +0000 (Tue, 17 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0292");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0292.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32359");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/03/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxpm' package(s) announced via the MGASA-2023-0292 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in libXpm due to a boundary condition within
the XpmCreateXpmImageFromBuffer() function. This flaw allows a local to
trigger an out-of-bounds read error and read the contents of memory on
the system. (CVE-2023-43788)

Out of bounds read on XPM with corrupted colormap. (CVE-2023-43789)");

  script_tag(name:"affected", value:"'libxpm' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64xpm-devel", rpm:"lib64xpm-devel~3.5.15~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xpm4", rpm:"lib64xpm4~3.5.15~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxpm", rpm:"libxpm~3.5.15~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxpm-devel", rpm:"libxpm-devel~3.5.15~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxpm4", rpm:"libxpm4~3.5.15~1.1.mga8", rls:"MAGEIA8"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64xpm-devel", rpm:"lib64xpm-devel~3.5.15~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xpm4", rpm:"lib64xpm4~3.5.15~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxpm", rpm:"libxpm~3.5.15~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxpm-devel", rpm:"libxpm-devel~3.5.15~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxpm4", rpm:"libxpm4~3.5.15~1.1.mga9", rls:"MAGEIA9"))) {
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
