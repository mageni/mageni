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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0392");
  script_cve_id("CVE-2022-26691");
  script_tag(name:"creation_date", value:"2022-10-28 12:41:25 +0000 (Fri, 28 Oct 2022)");
  script_version("2022-10-31T10:12:00+0000");
  script_tag(name:"last_modification", value:"2022-10-31 10:12:00 +0000 (Mon, 31 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 02:52:00 +0000 (Wed, 08 Jun 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0392)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0392");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0392.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30480");
  script_xref(name:"URL", value:"https://openprinting.github.io/cups-2.4.2/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7NQSHXNFEE2OGIYVYN23S2BDDQTAGLSJ/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5149");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5454-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/KQ6TD7F3VRITPEHFDHZHK7MU6FEBMZ5U/");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2022:4990");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/YQRIT4H75XV6M42K7ZTARWZ7YLLYQHPO/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the MGASA-2022-0392 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Authentication bypass and code execution vulnerability. (CVE-2022-26691)");

  script_tag(name:"affected", value:"'cups' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.3.3op2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~2.3.3op2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-filesystem", rpm:"cups-filesystem~2.3.3op2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-printerapp", rpm:"cups-printerapp~2.3.3op2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups2", rpm:"lib64cups2~2.3.3op2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups2-devel", rpm:"lib64cups2-devel~2.3.3op2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.3.3op2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~2.3.3op2~1.1.mga8", rls:"MAGEIA8"))) {
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
