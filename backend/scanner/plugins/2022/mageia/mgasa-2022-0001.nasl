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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0001");
  script_cve_id("CVE-2021-33285", "CVE-2021-33286", "CVE-2021-33287", "CVE-2021-33289", "CVE-2021-35266", "CVE-2021-35267", "CVE-2021-35268", "CVE-2021-35269", "CVE-2021-39251", "CVE-2021-39252", "CVE-2021-39253", "CVE-2021-39254", "CVE-2021-39255", "CVE-2021-39256", "CVE-2021-39257", "CVE-2021-39258", "CVE-2021-39259", "CVE-2021-39260", "CVE-2021-39261", "CVE-2021-39262", "CVE-2021-39263");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-20 17:04:00 +0000 (Mon, 20 Sep 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0001");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0001.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29428");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/08/30/1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5060-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/J6ACAL2OSY4MFKIQMETQG4T7ZJS2BVPE/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/APJMFOEFTZSFEAKDMRWUM25JNERJUHUT/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4971");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libguestfs, ntfs-3g, ntfs-3g-system-compression, partclone, testdisk, wimlib' package(s) announced via the MGASA-2022-0001 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security vulnerabilities were identified in the open source NTFS-3G and
NTFSPROGS software. These vulnerabilities may allow an attacker using a
maliciously crafted NTFS-formatted image file or external storage to
potentially execute arbitrary privileged code, if the attacker has either
local access and the ntfs-3g binary is setuid root, or if the attacker has
physical access to an external port to a computer which is configured to
run the ntfs-3g binary or one of the ntfsprogs tools when the external
storage is plugged into the computer. These vulnerabilities result from
incorrect validation of some of the NTFS metadata that could potentially
cause buffer overflows, which could be exploited by an attacker. Common
ways for attackers to gain physical access to a machine is through
social engineering or an evil maid attack on an unattended computer.");

  script_tag(name:"affected", value:"'libguestfs, ntfs-3g, ntfs-3g-system-compression, partclone, testdisk, wimlib' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ntfs-3g-devel", rpm:"lib64ntfs-3g-devel~2021.8.22~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ntfs-3g89", rpm:"lib64ntfs-3g89~2021.8.22~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wim-devel", rpm:"lib64wim-devel~1.13.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wim15", rpm:"lib64wim15~1.13.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs", rpm:"libguestfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-bash-completion", rpm:"libguestfs-bash-completion~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-devel", rpm:"libguestfs-devel~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-forensics", rpm:"libguestfs-forensics~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-gfs2", rpm:"libguestfs-gfs2~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-gobject", rpm:"libguestfs-gobject~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-gobject-devel", rpm:"libguestfs-gobject-devel~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-hfsplus", rpm:"libguestfs-hfsplus~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-inspect-icons", rpm:"libguestfs-inspect-icons~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-jfs", rpm:"libguestfs-jfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-man-pages-ja", rpm:"libguestfs-man-pages-ja~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-man-pages-uk", rpm:"libguestfs-man-pages-uk~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-nilfs", rpm:"libguestfs-nilfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-reiserfs", rpm:"libguestfs-reiserfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-rescue", rpm:"libguestfs-rescue~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-rsync", rpm:"libguestfs-rsync~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-tools", rpm:"libguestfs-tools~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-tools-c", rpm:"libguestfs-tools-c~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-ufs", rpm:"libguestfs-ufs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-vala", rpm:"libguestfs-vala~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-xfs", rpm:"libguestfs-xfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-zfs", rpm:"libguestfs-zfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g-devel", rpm:"libntfs-3g-devel~2021.8.22~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g89", rpm:"libntfs-3g89~2021.8.22~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwim-devel", rpm:"libwim-devel~1.13.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwim15", rpm:"libwim15~1.13.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua-guestfs", rpm:"lua-guestfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2021.8.22~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g-system-compression", rpm:"ntfs-3g-system-compression~1.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-libguestfs", rpm:"ocaml-libguestfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-libguestfs-devel", rpm:"ocaml-libguestfs-devel~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"partclone", rpm:"partclone~0.3.18~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Sys-Guestfs", rpm:"perl-Sys-Guestfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"photorec", rpm:"photorec~7.1~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libguestfs", rpm:"python3-libguestfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libguestfs", rpm:"ruby-libguestfs~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"testdisk", rpm:"testdisk~7.1~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virt-dib", rpm:"virt-dib~1.44.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wimlib", rpm:"wimlib~1.13.3~1.2.mga8", rls:"MAGEIA8"))) {
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
