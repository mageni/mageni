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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0385");
  script_cve_id("CVE-2021-46790", "CVE-2022-30783", "CVE-2022-30784", "CVE-2022-30785", "CVE-2022-30786", "CVE-2022-30787", "CVE-2022-30788", "CVE-2022-30789");
  script_tag(name:"creation_date", value:"2022-10-24 04:53:32 +0000 (Mon, 24 Oct 2022)");
  script_version("2022-10-24T04:53:32+0000");
  script_tag(name:"last_modification", value:"2022-10-24 04:53:32 +0000 (Mon, 24 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-28 18:47:00 +0000 (Wed, 28 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0385)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0385");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0385.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30479");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/05/26/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/05/26/2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5452-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/06/07/4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5463-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5160");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/7JPX6OUCQKZX4PN5DQPVDUFZCOOZUX7Z/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CUCIRAD67WWT3IZWCVN25JFFBTDANX5J/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs-3g' package(s) announced via the MGASA-2022-0385 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ntfsck in NTFS-3G through 2021.8.22 has a heap-based buffer overflow
involving buffer+512*3-2. (CVE-2021-46790)

An invalid return code in fuse_kern_mount enables intercepting of
libfuse-lite protocol traffic between NTFS-3G and the kernel in NTFS-3G
through 2021.8.22 when using libfuse-lite. (CVE-2022-30783)

A crafted NTFS image can cause heap exhaustion in ntfs_get_attribute_value
in NTFS-3G through 2021.8.22. (CVE-2022-30784)

A file handle created in fuse_lib_opendir, and later used in
fuse_lib_readdir, enables arbitrary memory read and write operations in
NTFS-3G through 2021.8.22 when using libfuse-lite. (CVE-2022-30785)

A crafted NTFS image can cause a heap-based buffer overflow in
ntfs_names_full_collate in NTFS-3G through 2021.8.22. (CVE-2022-30786)

An integer underflow in fuse_lib_readdir enables arbitrary memory read
operations in NTFS-3G through 2021.8.22 when using libfuse-lite.
(CVE-2022-30787)

A crafted NTFS image can cause a heap-based buffer overflow in
ntfs_mft_rec_alloc in NTFS-3G through 2021.8.22. (CVE-2022-30788)

A crafted NTFS image can cause a heap-based buffer overflow
in ntfs_check_log_client_array in NTFS-3G through 2021.8.22.
(CVE-2022-30789)");

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ntfs-3g-devel", rpm:"lib64ntfs-3g-devel~2021.8.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ntfs-3g89", rpm:"lib64ntfs-3g89~2021.8.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g-devel", rpm:"libntfs-3g-devel~2021.8.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g89", rpm:"libntfs-3g89~2021.8.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2021.8.22~1.1.mga8", rls:"MAGEIA8"))) {
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
