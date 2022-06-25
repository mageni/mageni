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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0076");
  script_cve_id("CVE-2021-37600", "CVE-2021-3995", "CVE-2021-3996", "CVE-2022-0563");
  script_tag(name:"creation_date", value:"2022-02-23 03:14:32 +0000 (Wed, 23 Feb 2022)");
  script_version("2022-02-23T03:14:32+0000");
  script_tag(name:"last_modification", value:"2022-02-23 03:14:32 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-12 19:54:00 +0000 (Thu, 12 Aug 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0076)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0076");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0076.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29565");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-October/009610.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/01/24/2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5055");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SW73IARDAP7WWQ6ETYQB2OS2SLW4XTT3/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5279-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2YUFRTN7YYS4ESW372SWK2PURGSGVDL4/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/02/17/2");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/utils/util-linux/v2.36/v2.36.2-ReleaseNotes");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/utils/util-linux/v2.36/v2.36.2-ReleaseNotes");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'util-linux' package(s) announced via the MGASA-2022-0076 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow in util-linux through 2.37.1 can potentially cause a
buffer overflow if an attacker were able to use system resources in a way
that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is
unexploitable in GNU C Library environments, and possibly in all realistic
environments. (CVE-2021-37600)

Unauthorized unmount of FUSE filesystems belonging to users with similar
uid. (CVE-2021-3995)

Unauthorized unmount of filesystems in libmount (CVE-2021-3996)

A flaw was found in the util-linux chfn and chsh utilities when compiled
with Readline support. The Readline library uses an 'INPUTRC' environment
variable to get a path to the library config file. When the library cannot
parse the specified file, it prints an error message containing data from
the file. This flaw allows an unprivileged user to read root-owned files,
potentially leading to privilege escalation. This flaw affects util-linux
versions prior to 2.37.4. (CVE-2022-0563)

Additional bug fixes included by updating to version 2.36.2. See release
notes for details.");

  script_tag(name:"affected", value:"'util-linux' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64blkid-devel", rpm:"lib64blkid-devel~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64blkid1", rpm:"lib64blkid1~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fdisk-devel", rpm:"lib64fdisk-devel~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fdisk1", rpm:"lib64fdisk1~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mount-devel", rpm:"lib64mount-devel~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mount1", rpm:"lib64mount1~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smartcols-devel", rpm:"lib64smartcols-devel~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smartcols1", rpm:"lib64smartcols1~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64uuid-devel", rpm:"lib64uuid-devel~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64uuid1", rpm:"lib64uuid1~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid-devel", rpm:"libblkid-devel~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid1", rpm:"libblkid1~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk-devel", rpm:"libfdisk-devel~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk1", rpm:"libfdisk1~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount-devel", rpm:"libmount-devel~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount1", rpm:"libmount1~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols-devel", rpm:"libsmartcols-devel~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols1", rpm:"libsmartcols1~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid-devel", rpm:"libuuid-devel~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1", rpm:"libuuid1~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libmount", rpm:"python3-libmount~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.36.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uuidd", rpm:"uuidd~2.36.2~1.mga8", rls:"MAGEIA8"))) {
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
