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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0384");
  script_cve_id("CVE-2022-1304");
  script_tag(name:"creation_date", value:"2022-10-24 04:53:32 +0000 (Mon, 24 Oct 2022)");
  script_version("2022-10-24T04:53:32+0000");
  script_tag(name:"last_modification", value:"2022-10-24 04:53:32 +0000 (Mon, 24 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-21 15:36:00 +0000 (Thu, 21 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0384)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0384");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0384.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30423");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-May/010997.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HV3R6DJ424I5JBDSF3ZYYH63VRSXB65J/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5464-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'e2fsprogs' package(s) announced via the MGASA-2022-0384 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5.
This issue leads to a segmentation fault and possibly arbitrary code
execution via a specially crafted filesystem. (CVE-2022-1304)");

  script_tag(name:"affected", value:"'e2fsprogs' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs", rpm:"e2fsprogs~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"e2scrub", rpm:"e2scrub~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64com_err-devel", rpm:"lib64com_err-devel~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64com_err2", rpm:"lib64com_err2~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ext2fs-devel", rpm:"lib64ext2fs-devel~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ext2fs2", rpm:"lib64ext2fs2~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ss-devel", rpm:"lib64ss-devel~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ss2", rpm:"lib64ss2~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err-devel", rpm:"libcom_err-devel~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err2", rpm:"libcom_err2~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs-devel", rpm:"libext2fs-devel~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs2", rpm:"libext2fs2~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libss-devel", rpm:"libss-devel~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libss2", rpm:"libss2~1.45.6~6.1.mga8", rls:"MAGEIA8"))) {
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
