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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0354");
  script_cve_id("CVE-2016-8605", "CVE-2016-8606");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-18 16:27:00 +0000 (Wed, 18 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0354)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0354");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0354.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19567");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/10/12/1");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/10/12/2");
  script_xref(name:"URL", value:"http://lwn.net/Vulnerabilities/703769/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'guile' package(s) announced via the MGASA-2016-0354 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The 'mkdir' procedure of GNU Guile, an implementation of the Scheme
programming language, temporarily changed the process' umask to zero.
During that time window, in a multithreaded application, other threads
could end up creating files with insecure permissions (CVE-2016-8605).

GNU Guile, an implementation of the Scheme language, provides a 'REPL
server' which is a command prompt that developers can connect to for
live coding and debugging purposes. The REPL server is vulnerable to the
HTTP inter-protocol attack. This constitutes a remote code execution
vulnerability for developers running a REPL server that listens on a
loopback device or private network (CVE-2016-8606).

The guile package has been updated to version 2.0.13, fixing these
issues and other bugs. See the upstream release announcements for
details.");

  script_tag(name:"affected", value:"'guile' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"guile", rpm:"guile~2.0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"guile-runtime", rpm:"guile-runtime~2.0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64guile-devel", rpm:"lib64guile-devel~2.0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64guile2.0_22", rpm:"lib64guile2.0_22~2.0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64guilereadline18_18", rpm:"lib64guilereadline18_18~2.0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguile-devel", rpm:"libguile-devel~2.0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguile2.0_22", rpm:"libguile2.0_22~2.0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguilereadline18_18", rpm:"libguilereadline18_18~2.0.13~1.mga5", rls:"MAGEIA5"))) {
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
