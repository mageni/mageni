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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0340");
  script_cve_id("CVE-2018-10840", "CVE-2018-10853", "CVE-2018-1087", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-1118", "CVE-2018-11412", "CVE-2018-12904", "CVE-2018-13405", "CVE-2018-14678", "CVE-2018-5390", "CVE-2018-6412", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0340)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0340");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0340.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23418");
  script_xref(name:"URL", value:"https://www.securityweek.com/segmentsmack-flaw-linux-kernel-allows-remote-dos-attacks");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.45");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.46");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.47");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.48");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.49");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.50");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.51");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.52");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.53");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.54");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.55");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.56");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.57");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.58");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.59");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.60");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.61");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.62");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2018-0340 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on the upstream 4.14.62 and fixes at least
the following security issues:

kernel KVM before versions kernel 4.16, kernel 4.16-rc7, kernel 4.17-rc1,
kernel 4.17-rc2 and kernel 4.17-rc3 is vulnerable to a flaw in the way the
Linux kernel's KVM hypervisor handled exceptions delivered after a stack
switch operation via Mov SS or Pop SS instructions. During the stack switch
operation, the processor did not deliver interrupts and exceptions, rather
they are delivered once the first instruction after the stack switch is
executed. An unprivileged KVM guest user could use this flaw to crash the
guest or, potentially, escalate their privileges in the guest
(CVE-2018-1087).

Linux kernel vhost since version 4.8 does not properly initialize memory in
messages passed between virtual guests and the host operating system in the
vhost/vhost.c:vhost_new_msg() function. This can allow local privileged
users to read some kernel memory contents when reading from the
/dev/vhost-net device file (CVE-2018-1118).

Security researchers from FICORA have identified a remote denial of
service attack against the Linux kernel caused by inefficient
implementation of TCP segment reassembly, named 'SegmentSmack'.
A remote attacker could consume a lot of CPU resources in the kernel
networking stack with just a low bandwidth or single host attack by
using lots of small TCP segments packets. Usually large botnets are
needed for similar effect. The rate needed for this denial of service
attack to be effective is several magnitudes lower than the usual
packet processing capability of the machine, as the attack exploits
worst case behaviour of existing algorithms (CVE-2018-5390).
In the function sbusfb_ioctl_helper() in drivers/video/fbdev/sbuslib.c
in the Linux kernel through 4.15, an integer signedness error allows
arbitrary information leakage for the FBIOPUTCMAP_SPARC and
FBIOGETCMAP_SPARC commands (CVE-2018-6412).

In some circumstances, some operating systems or hypervisors may not expect
or properly handle an Intel architecture hardware debug exception. The error
appears to be due to developer interpretation of existing documentation for
certain Intel architecture interrupt/exception instructions, namely MOV SS
and POP SS. An authenticated attacker may be able to read sensitive data in
memory or control low-level operating system functions (CVE-2018-8897).

Linux kernel is vulnerable to a heap-based buffer overflow in the
fs/ext4/xattr.c:ext4_xattr_set_entry() function. An attacker could exploit
this by operating on a mounted crafted ext4 image (CVE-2018-10840).

The kvm functions that were used in the emulation of fxrstor, fxsave,
sgdt and sidt were originally meant for task switching, and as such they
did not check privilege levels. This allowed guest userspace to guest
kernel write (CVE-2018-10853).

A flaw was found in Linux kernel ext4 File System. A use-after-free ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.14.62~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.14.62-1.mga6", rpm:"kernel-tmb-desktop-4.14.62-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.14.62-1.mga6", rpm:"kernel-tmb-desktop-devel-4.14.62-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.14.62~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.14.62~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.14.62-1.mga6", rpm:"kernel-tmb-source-4.14.62-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.14.62~1.mga6", rls:"MAGEIA6"))) {
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
