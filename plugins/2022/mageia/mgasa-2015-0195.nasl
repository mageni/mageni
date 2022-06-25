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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0195");
  script_cve_id("CVE-2013-7423", "CVE-2014-8121", "CVE-2015-1781");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-17 19:36:00 +0000 (Mon, 17 Jun 2019)");

  script_name("Mageia: Security Advisory (MGASA-2015-0195)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0195");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0195.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15800");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15545");
  script_xref(name:"URL", value:"https://sourceware.org/bugzilla/show_bug.cgi?id=16009");
  script_xref(name:"URL", value:"https://sourceware.org/bugzilla/show_bug.cgi?id=17269");
  script_xref(name:"URL", value:"https://sourceware.org/bugzilla/show_bug.cgi?id=18032");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2015-0327.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2015-0863.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the MGASA-2015-0195 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated glibc package fixes security vulnerabilities:

It was discovered that, under certain circumstances, glibc's getaddrinfo()
function would send DNS queries to random file descriptors. An attacker
could potentially use this flaw to send DNS queries to unintended
recipients, resulting in information disclosure or data loss due to the
application encountering corrupted data. (CVE-2013-7423)

It was found that the files back end of Name Service Switch (NSS) did not
isolate iteration over an entire database from key-based look-up API calls.
An application performing look-ups on a database while iterating over it
could enter an infinite loop, leading to a denial of service.
(CVE-2014-8121)

A buffer overflow flaw was found in the way glibc's gethostbyname_r() and
other related functions computed the size of a buffer when passed a
misaligned buffer as input. An attacker able to make an application call
any of these functions with a misaligned buffer could use this flaw to
crash the application or, potentially, execute arbitrary code with the
permissions of the user running the application. (CVE-2015-1781)

Joseph Myers discovered strxfrm is vulnerable to integer overflows
when computing memory allocation sizes (similar to CVE-2012-4412)
[BZ #16009] (CVE pending)

Shaun Colley discovered strxfrm falls back to an unbounded alloca if
malloc fails making it vulnerable to stack-based buffer overflows
(similar to CVE-2012-4424) [BZ #16009] (CVE pending)

A buffer overflow flaw was found in libio/wstrops.c:_IO_wstr_overflow
which allows for overflow in calculating the new size in wide characters,
but not for overflow in the multiplication to compute the size in bytes,
which could thus overflow and result in a buffer overrun copying data
into the new buffer. [BZ #17269] (CVE pending)

When processing certain malformed patterns, fnmatch can skip over the
NUL byte terminating the pattern. This can potentially result in an
application crash if fnmatch hits an unmapped page before encountering a
NUL byte. [BZ #18032] (CVE pending)

Other fixes in this update:
nscd package was missing the /var/db/nscd directory which prevented
it to work properly (mga#15545).");

  script_tag(name:"affected", value:"'glibc' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.18~9.11.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.18~9.11.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.18~9.11.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.18~9.11.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.18~9.11.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.18~9.11.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.18~9.11.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.18~9.11.mga4", rls:"MAGEIA4"))) {
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
