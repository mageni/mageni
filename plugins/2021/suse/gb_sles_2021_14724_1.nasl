# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14724.1");
  script_cve_id("CVE-2020-35519", "CVE-2020-36322", "CVE-2021-20261", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-28950", "CVE-2021-28972", "CVE-2021-29650", "CVE-2021-30002", "CVE-2021-3483");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-09T14:56:38+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-18 10:15:00 +0000 (Fri, 18 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14724-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4|SLES11\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14724-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114724-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:14724-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-3483: Fixed a use-after-free in nosy.c (bsc#1184393).

CVE-2021-30002: Fixed a memory leak for large arguments in
 video_usercopy (bsc#1184120).

CVE-2021-29650: Fixed an issue where the netfilter subsystem allowed
 attackers to cause a denial of service (bsc#1184208).

CVE-2021-28972: Fixed a user-tolerable buffer overflow when writing a
 new device name to the driver from userspace, allowing userspace to
 write data to the kernel stack frame directly (bsc#1184198).

CVE-2021-28950: Fixed an infinite loop because a retry loop continually
 finds the same bad inode (bsc#1184194).

CVE-2021-27365: Fixed an issue where an unprivileged user can send a
 Netlink message that is associated with iSCSI, and has a length up to
 the maximum length of a Netlink message (bsc#1182715).

CVE-2021-27364: Fixed an issue where an attacker could craft Netlink
 messages (bsc#1182717).

CVE-2021-27363: Fixed a kernel pointer leak which could have been used
 to determine the address of the iscsi_transport structure (bsc#1182716).

CVE-2021-20261: Fixed a race condition in the implementation of the
 floppy disk drive controller driver software (bsc#1183400).

CVE-2020-36322: Fixed an issue in the FUSE filesystem implementation
 which could have caused a system crash (bsc#1184211).

CVE-2020-35519: Fixed an out-of-bounds memory access was found in
 x25_bind (bsc#1183696).

The following non-security bugs were fixed:

md: md.c: Return -ENODEV when mddev is NULL in rdev_attr_show
 (bsc#1056134, bsc#1180963).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Debuginfo 11-SP4");

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

if(release == "SLES11.0SP4") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.126.1", rls:"SLES11.0SP4"))){
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.126.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.126.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.126.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.126.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.126.1", rls:"SLES11.0"))){
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
