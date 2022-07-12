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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0336");
  script_cve_id("CVE-2014-0206", "CVE-2014-1739", "CVE-2014-3153", "CVE-2014-3917", "CVE-2014-4014", "CVE-2014-4171", "CVE-2014-4508", "CVE-2014-5045", "CVE-2014-5077");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-08 16:25:00 +0000 (Mon, 08 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2014-0336)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0336");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0336.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13863");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.26");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.25");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.24");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.23");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.22");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.21");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2014-0336 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated kernel-linus provides upstream 3.12.26 kernel and fixes the
following security issues:

Array index error in the aio_read_events_ring function in fs/aio.c in
the Linux kernel through 3.15.1 allows local users to obtain sensitive
information from kernel memory via a large head value (CVE-2014-0206).

media-device: fix infoleak in ioctl media_enum_entities()
(CVE-2014-1739)

The futex_requeue function in kernel/futex.c in the Linux kernel through
3.14.5 does not ensure that calls have two different futex addresses,
which allows local users to gain privileges via a crafted FUTEX_REQUEUE
command that facilitates unsafe waiter modification. (CVE-2014-3153)

kernel/auditsc.c in the Linux kernel through 3.14.5, when
CONFIG_AUDITSYSCALL is enabled with certain syscall rules, allows local
users to obtain potentially sensitive single-bit values from kernel memory
or cause a denial of service (OOPS) via a large value of a syscall number.
To avoid this and other issues CONFIG_AUDITSYSCALL has been disabled.
(CVE-2014-3917)

The capabilities implementation in the Linux kernel before 3.14.8 does
not properly consider that namespaces are inapplicable to inodes, which
allows local users to bypass intended chmod restrictions by first creating
a user namespace, as demonstrated by setting the setgid bit on a file with
group ownership of root (CVE-2014-4014)

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

A flaw was found in the way reference counting was handled in the Linux
kernels VFS subsystem when unmount on symlink was performed. An unprivileged
local user could use this flaw to cause OOM conditions leading to denial
of service or, potentially, trigger use-after-free error (CVE-2014-5045).

Linux kernel built with the support for Stream Control Transmission Protocol
(CONFIG_IP_SCTP) is vulnerable to a NULL pointer dereference flaw. It could
occur when simultaneous new connections are initiated between the same pair
of hosts. A remote user/program could use this flaw to crash the system
kernel resulting in DoS (CVE.2014-5077).

For other fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-3.12.26-1.mga4", rpm:"kernel-linus-3.12.26-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~3.12.26~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-3.12.26-1.mga4", rpm:"kernel-linus-devel-3.12.26-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~3.12.26~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~3.12.26~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~3.12.26~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-3.12.26-1.mga4", rpm:"kernel-linus-source-3.12.26-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~3.12.26~1.mga4", rls:"MAGEIA4"))) {
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
