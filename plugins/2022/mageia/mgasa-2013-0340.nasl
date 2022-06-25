# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0340");
  script_cve_id("CVE-2012-4412", "CVE-2012-4424", "CVE-2013-2207", "CVE-2013-4237", "CVE-2013-4332", "CVE-2013-4458", "CVE-2013-4788");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-13 21:29:00 +0000 (Thu, 13 Jun 2019)");

  script_name("Mageia: Security Advisory (MGASA-2013-0340)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0340");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0340.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11059");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=855385");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=858238");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=976408");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=995839");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1007545");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=985625");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1022280");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc, glibc' package(s) announced via the MGASA-2013-0340 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated glibc packages fixes the following security issues:

Integer overflow in string/strcoll_l.c in the GNU C Library (aka glibc
or libc6) 2.17 and earlier allows context-dependent attackers to cause
a denial of service (crash) or possibly execute arbitrary code via a
long string, which triggers a heap-based buffer overflow. (CVE-2012-4412)

Stack-based buffer overflow in string/strcoll_l.c in the GNU C Library
(aka glibc or libc6) 2.17 and earlier allows context-dependent
attackers to cause a denial of service (crash) or possibly execute
arbitrary code via a long string that triggers a malloc failure and
use of the alloca function. (CVE-2012-4424)

pt_chown in GNU C Library (aka glibc or libc6) before 2.18 does not
properly check permissions for tty files, which allows local users to
change the permission on the files and obtain access to arbitrary
pseudo-terminals by leveraging a FUSE file system. (CVE-2013-2207)
NOTE! This is fixed by removing pt_chown which may break chroots
 if their devpts was not mounted correctly.
 (make sure to mount the devpts correctly with gid=5)

sysdeps/posix/readdir_r.c in the GNU C Library (aka glibc or libc6)
2.18 and earlier allows context-dependent attackers to cause a denial
of service (out-of-bounds write and crash) or possibly execute
arbitrary code via a crafted (1) NTFS or (2) CIFS image. (CVE-2013-4237)

Multiple integer overflows in malloc/malloc.c in the GNU C Library
(aka glibc or libc6) 2.18 and earlier allow context-dependent
attackers to cause a denial of service (heap corruption) via a large
value to the (1) pvalloc, (2) valloc, (3) posix_memalign, (4)
memalign, or (5) aligned_alloc functions. (CVE-2013-4332)

A stack (frame) overflow flaw, which led to a denial of service
(application crash), was found in the way glibc's getaddrinfo() function
processed certain requests when called with AF_INET6. A similar flaw to
CVE-2013-1914, this affects AF_INET6 rather than AF_UNSPEC (CVE-2013-4458).

The PTR_MANGLE implementation in the GNU C Library (aka glibc or libc6)
2.4, 2.17, and earlier, and Embedded GLIBC (EGLIBC) does not initialize
the random value for the pointer guard, which makes it easier for context-
dependent attackers to control execution flow by leveraging a buffer-
overflow vulnerability in an application and using the known zero value
pointer guard to calculate a pointer address. (CVE-2013-4788)

Other fixes in this update:
- Correct the processing of '\x80' characters in crypt_freesec.c
- drop minimal required kernel to 2.6.32 so it works in chroots on top
 of enterprise kernels and for OpenVZ users.
- fix typo in nscd.service");

  script_tag(name:"affected", value:"'glibc, glibc' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.14.1~11.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.14.1~11.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.14.1~11.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc-pdf", rpm:"glibc-doc-pdf~2.14.1~11.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.14.1~11.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.14.1~11.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.14.1~11.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.14.1~11.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.14.1~11.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.17~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.17~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.17~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.17~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~7.2.mga3", rls:"MAGEIA3"))) {
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
