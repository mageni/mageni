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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0264");
  script_cve_id("CVE-2017-5754", "CVE-2018-1000004", "CVE-2018-1000200", "CVE-2018-1065", "CVE-2018-1068", "CVE-2018-1087", "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-1094", "CVE-2018-1095", "CVE-2018-1120", "CVE-2018-1130", "CVE-2018-3639", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0264)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0264");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0264.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23076");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.19");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.20");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.21");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.22");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.23");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.24");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.25");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.26");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.27");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.28");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.29");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.30");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.31");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.32");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.33");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.34");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.35");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.36");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.37");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.38");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.39");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.40");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.41");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.42");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.43");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.44");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2018-0264 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on the upstream 4.14.44 and fixes at least
the following security issues:

This update adds KPTI mitigation for Meltdown (CVE-2017-5754) on 32bit x86.

The netfilter subsystem in the Linux kernel through 4.15.7 mishandles the
case of a rule blob that contains a jump but lacks a user-defined chain,
which allows local users to cause a denial of service (NULL pointer
dereference) by leveraging the CAP_NET_RAW or CAP_NET_ADMIN capability,
related to arpt_do_table in net/ipv4/netfilter/arp_tables.c, ipt_do_table
in net/ipv4/netfilter/ip_tables.c, and ip6t_do_table in
net/ipv6/netfilter/ip6_tables.c (CVE-2018-1065).

A flaw was found in the Linux kernel implementation of 32 bit syscall
interface for bridging allowing a privileged user to arbitrarily write
to a limited range of kernel memory. This flaw can be exploited not only
by a system's privileged user (a real 'root' user), but also by an
attacker who is a privileged user (a 'root' user) in a user+network
namespace (CVE-2018-1068).

On x86, MOV SS and POP SS behave strangely if they encounter a data
breakpoint. If this occurs in a KVM guest, KVM incorrectly thinks that
a #DB instruction was caused by the undocumented ICEBP instruction. This
results in #DB being delivered to the guest kernel with an incorrect RIP
on the stack. On most guest kernels, this will allow a guest user to DoS
the guest kernel or even to escalate privilege to that of the guest kernel
(CVE-2018-1087).

The ext4_iget function in fs/ext4/inode.c in the Linux kernel through
4.15.15 mishandles the case of a root directory with a zero i_links_count,
which allows attackers to cause a denial of service (ext4_process_freed_data
NULL pointer dereference and OOPS) via a crafted ext4 image (CVE-2018-1092).

The ext4_valid_block_bitmap function in fs/ext4/balloc.c in the Linux kernel
through 4.15.15 allows attackers to cause a denial of service (out-of-bounds
read and system crash) via a crafted ext4 image because balloc.c and ialloc.c
do not validate bitmap block numbers (CVE-2018-1093).

The ext4_fill_super function in fs/ext4/super.c in the Linux kernel through
4.15.15 does not always initialize the crc32c checksum driver, which allows
attackers to cause a denial of service (ext4_xattr_inode_hash NULL pointer
dereference and system crash) via a crafted ext4 image (CVE-2018-1094).

The ext4_xattr_check_entries function in fs/ext4/xattr.c in the Linux kernel
through 4.15.15 does not properly validate xattr sizes, which causes
misinterpretation of a size as an error code, and consequently allows
attackers to cause a denial of service (get_acl NULL pointer dereference and
system crash) via a crafted ext4 image (CVE-2018-1095).

By mmap()ing a FUSE-backed file onto a process's memory containing command
line arguments (or environment strings), an attacker can cause utilities
from psutils or procps (such as ps, w) or any other program ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.14.44~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.14.44-2.mga6", rpm:"kernel-tmb-desktop-4.14.44-2.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.14.44-2.mga6", rpm:"kernel-tmb-desktop-devel-4.14.44-2.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.14.44~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.14.44~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.14.44-2.mga6", rpm:"kernel-tmb-source-4.14.44-2.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.14.44~2.mga6", rls:"MAGEIA6"))) {
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
