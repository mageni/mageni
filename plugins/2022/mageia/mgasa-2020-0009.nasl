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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0009");
  script_cve_id("CVE-2019-11707", "CVE-2019-11708");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-15 18:15:00 +0000 (Thu, 15 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0009");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0009.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25910");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OS4TDQ75LLRCFOAXMPHTQE6XCPJGZQ6X/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/ZS2X4UWVWTNTNWOCAJYQO77GGSSI3H6K/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gjs, mozjs60' package(s) announced via the MGASA-2020-0009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

A type confusion vulnerability can occur when manipulating JavaScript
objects due to issues in Array.pop. This can allow for an exploitable
crash. We are aware of targeted attacks in the wild abusing this flaw.
This vulnerability affects Firefox ESR < 60.7.1, Firefox < 67.0.3,
and Thunderbird < 60.7.2. (CVE-2019-11707)

Insufficient vetting of parameters passed with the Prompt:Open IPC message
between child and parent processes can result in the non-sandboxed parent
process opening web content chosen by a compromised child process. When
combined with additional vulnerabilities this could result in executing
arbitrary code on the user's computer. This vulnerability affects Firefox
ESR < 60.7.2, Firefox < 67.0.4, and Thunderbird < 60.7.2. (CVE-2019-11708)

The mozjs60 package has been updated to version 60.9.0, fixing these issues
and other bugs. The gjs package has been rebuilt against the updated mozjs60.");

  script_tag(name:"affected", value:"'gjs, mozjs60' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"gjs", rpm:"gjs~1.56.2~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gjs-common", rpm:"gjs-common~1.56.2~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gjs-devel", rpm:"lib64gjs-devel~1.56.2~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gjs-gir1.0", rpm:"lib64gjs-gir1.0~1.56.2~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gjs0", rpm:"lib64gjs0~1.56.2~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mozjs60", rpm:"lib64mozjs60~60.9.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mozjs60-devel", rpm:"lib64mozjs60-devel~60.9.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgjs-devel", rpm:"libgjs-devel~1.56.2~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgjs-gir1.0", rpm:"libgjs-gir1.0~1.56.2~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgjs0", rpm:"libgjs0~1.56.2~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmozjs60", rpm:"libmozjs60~60.9.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmozjs60-devel", rpm:"libmozjs60-devel~60.9.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs60", rpm:"mozjs60~60.9.0~1.mga7", rls:"MAGEIA7"))) {
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
