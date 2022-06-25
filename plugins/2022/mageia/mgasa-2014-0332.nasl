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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0332");
  script_cve_id("CVE-2014-0181", "CVE-2014-0206", "CVE-2014-1739", "CVE-2014-3153", "CVE-2014-3917", "CVE-2014-4014", "CVE-2014-4171", "CVE-2014-4508");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-08 16:25:00 +0000 (Mon, 08 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2014-0332)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0332");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0332.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13869");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.51");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.50");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.49");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.48");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.47");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.46");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.45");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.44");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.43");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.42");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.41");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-vserver, kernel-vserver' package(s) announced via the MGASA-2014-0332 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated kernel-vserver provides upstream 3.10.51 kernel and fixes the
following security issues:

Array index error in the aio_read_events_ring function in fs/aio.c in
the Linux kernel through 3.15.1 allows local users to obtain sensitive
information from kernel memory via a large head value (CVE-2014-0206).

The Netlink implementation in the Linux kernel through 3.14.1 does not
provide a mechanism for authorizing socket operations based on the
opener of a socket, which allows local users to bypass intended access
restrictions and modify network configurations by using a Netlink socket
for the (1) stdout or (2) stderr of a setuid program. (CVE-2014-0181)

media-device: fix infoleak in ioctl media_enum_entities()
(CVE-2014-1739)

The futex_requeue function in kernel/futex.c in the Linux kernel through
3.14.5 does not ensure that calls have two different futex addresses,
which allows local users to gain privileges via a crafted FUTEX_REQUEUE
command that facilitates unsafe waiter modification. (CVE-2014-3153)

kernel/auditsc.c in the Linux kernel through 3.14.5, when AUDITSYSCALL
is enabled with certain syscall rules, allows local users to obtain
potentially sensitive single-bit values from kernel memory or cause a
denial of service (OOPS) via a large value of a syscall number.
(CVE-2014-3917)

Andy Lutomirski has reported a vulnerability in Linux Kernel, which can
be exploited by malicious, local users to gain escalated privileges.
The vulnerability is caused due to an error related to checking Inode
capabilities, which can be exploited to conduct certain actions with
escalated privileges.
Successful exploitation requires a kernel built with user namespaces
(USER_NS) enabled. (CVE-2014-4014)

mm/shmem.c in the Linux kernel through 3.15.1 does not properly implement
the interaction between range notification and hole punching, which allows
local users to cause a denial of service (i_mutex hold) by using the mmap
system call to access a hole, as demonstrated by interfering with intended
shmem activity by blocking completion of (1) an MADV_REMOVE madvise call
or (2) an FALLOC_FL_PUNCH_HOLE fallocate call (CVE-2014-4171).

arch/x86/kernel/entry_32.S in the Linux kernel through 3.15.1 on 32-bit
x86 platforms, when syscall auditing is enabled and the sep CPU feature
flag is set, allows local users to cause a denial of service (OOPS and
system crash) via an invalid syscall number, as demonstrated by number
1000 (CVE-2014-4508).

For other fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-vserver, kernel-vserver' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-3.10.51-0.vs2.3.6.8.1.mga3", rpm:"kernel-vserver-3.10.51-0.vs2.3.6.8.1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver", rpm:"kernel-vserver~3.10.51~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-devel-3.10.51-0.vs2.3.6.8.1.mga3", rpm:"kernel-vserver-devel-3.10.51-0.vs2.3.6.8.1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-devel-latest", rpm:"kernel-vserver-devel-latest~3.10.51~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-doc", rpm:"kernel-vserver-doc~3.10.51~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-latest", rpm:"kernel-vserver-latest~3.10.51~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-source-3.10.51-0.vs2.3.6.8.1.mga3", rpm:"kernel-vserver-source-3.10.51-0.vs2.3.6.8.1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-source-latest", rpm:"kernel-vserver-source-latest~3.10.51~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-3.10.51-0.vs2.3.6.8.1.mga4", rpm:"kernel-vserver-3.10.51-0.vs2.3.6.8.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver", rpm:"kernel-vserver~3.10.51~0.vs2.3.6.8.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-devel-3.10.51-0.vs2.3.6.8.1.mga4", rpm:"kernel-vserver-devel-3.10.51-0.vs2.3.6.8.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-devel-latest", rpm:"kernel-vserver-devel-latest~3.10.51~0.vs2.3.6.8.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-doc", rpm:"kernel-vserver-doc~3.10.51~0.vs2.3.6.8.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-latest", rpm:"kernel-vserver-latest~3.10.51~0.vs2.3.6.8.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-source-3.10.51-0.vs2.3.6.8.1.mga4", rpm:"kernel-vserver-source-3.10.51-0.vs2.3.6.8.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-source-latest", rpm:"kernel-vserver-source-latest~3.10.51~0.vs2.3.6.8.1.mga4", rls:"MAGEIA4"))) {
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
