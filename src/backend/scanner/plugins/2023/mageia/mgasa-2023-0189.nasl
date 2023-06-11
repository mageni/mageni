# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0189");
  script_cve_id("CVE-2023-24805");
  script_tag(name:"creation_date", value:"2023-06-01 04:13:29 +0000 (Thu, 01 Jun 2023)");
  script_version("2023-06-01T09:09:48+0000");
  script_tag(name:"last_modification", value:"2023-06-01 09:09:48 +0000 (Thu, 01 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-25 17:05:00 +0000 (Thu, 25 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0189)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0189");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0189.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31939");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/05/17/5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6083-1");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-May/014921.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/YNCGL2ZTAS2GFF23QFT55UFWIDMI4ZJK/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups-filters' package(s) announced via the MGASA-2023-0189 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Possible command injection in the Backend Error Handler (CVE-2023-24805)");

  script_tag(name:"affected", value:"'cups-filters' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups-filters", rpm:"cups-filters~1.28.7~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups-filters-devel", rpm:"lib64cups-filters-devel~1.28.7~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups-filters1", rpm:"lib64cups-filters1~1.28.7~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups-filters-devel", rpm:"libcups-filters-devel~1.28.7~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups-filters1", rpm:"libcups-filters1~1.28.7~1.1.mga8", rls:"MAGEIA8"))) {
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
