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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0318");
  script_cve_id("CVE-2019-10160", "CVE-2019-16056", "CVE-2019-16935", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-06 16:11:00 +0000 (Wed, 06 Jan 2021)");

  script_name("Mageia: Security Advisory (MGASA-2019-0318)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0318");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0318.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25641");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:1587");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:2030");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:3520");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4151-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python, python3' package(s) announced via the MGASA-2019-0318 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python and python3 packages fix security vulnerabilities:

An issue was discovered in urllib2 in Python 2.x through 2.7.16 and urllib
in Python 3.x through 3.7.2. CRLF injection is possible if the attacker
controls a url parameter, as demonstrated by the first argument to
urllib.request.urlopen with \r\n followed by an HTTP header or a Redis
command (CVE-2019-9740).

An issue was discovered in urllib2 in Python 2.x through 2.7.16 and urllib
in Python 3.x through 3.7.2. CRLF injection is possible if the attacker
controls a url parameter, as demonstrated by the first argument to
urllib.request.urlopen with \r\n (specifically in the path component of a
URL) followed by an HTTP header or a Redis command. This is similar to
CVE-2019-9740 query string issue (CVE-2019-9947).

urllib in Python 2.x through 2.7.16 supports the local_file: scheme, which
makes it easier for remote attackers to bypass protection mechanisms that
blacklist file: URIs, as demonstrated by triggering a
urllib.urlopen('local_file:///etc/passwd') call (CVE-2019-9948).

A security regression of CVE-2019-9636 was discovered in python, which
still allows an attacker to exploit CVE-2019-9636 by abusing the user and
password parts of a URL. When an application parses user-supplied URLs to
store cookies, authentication credentials, or other kind of information,
it is possible for an attacker to provide specially crafted URLs to make
the application locate host-related information (e.g. cookies,
authentication data) and send them to a different host than where it
should, unlike if the URLs had been correctly parsed. The result of an
attack may vary based on the application (CVE-2019-10160).

It was discovered that Python incorrectly parsed certain email addresses.
A remote attacker could possibly use this issue to trick Python
applications into accepting email addresses that should be denied
(CVE-2019-16056).

It was discovered that the Python documentation XML-RPC server incorrectly
handled certain fields. A remote attacker could use this issue to execute
a cross-site scripting (XSS) attack (CVE-2019-16935).");

  script_tag(name:"affected", value:"'python, python3' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64python-devel", rpm:"lib64python-devel~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7", rpm:"lib64python2.7~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7-stdlib", rpm:"lib64python2.7-stdlib~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7-testsuite", rpm:"lib64python2.7-testsuite~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3-devel", rpm:"lib64python3-devel~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.7", rpm:"lib64python3.7~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.7-stdlib", rpm:"lib64python3.7-stdlib~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.7-testsuite", rpm:"lib64python3.7-testsuite~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython-devel", rpm:"libpython-devel~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7", rpm:"libpython2.7~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7-stdlib", rpm:"libpython2.7-stdlib~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7-testsuite", rpm:"libpython2.7-testsuite~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3-devel", rpm:"libpython3-devel~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.7", rpm:"libpython3.7~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.7-stdlib", rpm:"libpython3.7-stdlib~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.7-testsuite", rpm:"libpython3.7-testsuite~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter-apps", rpm:"tkinter-apps~2.7.17~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3", rpm:"tkinter3~3.7.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3-apps", rpm:"tkinter3-apps~3.7.5~1.mga7", rls:"MAGEIA7"))) {
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
