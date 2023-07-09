# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0208");
  script_cve_id("CVE-2016-6153", "CVE-2018-8740");
  script_tag(name:"creation_date", value:"2023-06-29 04:13:13 +0000 (Thu, 29 Jun 2023)");
  script_version("2023-06-29T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-29 05:05:23 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2023-0208)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0208");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0208.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32018");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3431");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite' package(s) announced via the MGASA-2023-0208 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"os_unix.c in SQLite before 3.13.0 improperly implements the temporary
directory search algorithm, which might allow local users to obtain
sensitive information, cause a denial of service (application crash), or
have unspecified other impact by leveraging use of the current working
directory for temporary files. (CVE-2016-6153)
In SQLite through 3.22.0, databases whose schema is corrupted using a
CREATE TABLE AS statement could cause a NULL pointer dereference,
related to build.c and prepare (CVE-2018-8740)");

  script_tag(name:"affected", value:"'sqlite' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite0", rpm:"lib64sqlite0~2.8.17~26.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite0-devel", rpm:"lib64sqlite0-devel~2.8.17~26.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite0-static-devel", rpm:"lib64sqlite0-static-devel~2.8.17~26.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite0", rpm:"libsqlite0~2.8.17~26.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite0-devel", rpm:"libsqlite0-devel~2.8.17~26.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite0-static-devel", rpm:"libsqlite0-static-devel~2.8.17~26.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite", rpm:"sqlite~2.8.17~26.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-tools", rpm:"sqlite-tools~2.8.17~26.1.mga8", rls:"MAGEIA8"))) {
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
