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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0379");
  script_cve_id("CVE-2022-0171", "CVE-2022-20421", "CVE-2022-2308", "CVE-2022-2663", "CVE-2022-3061", "CVE-2022-3303", "CVE-2022-3586", "CVE-2022-39842", "CVE-2022-40307", "CVE-2022-40768", "CVE-2022-41674", "CVE-2022-42719", "CVE-2022-42720", "CVE-2022-42721", "CVE-2022-42722");
  script_tag(name:"creation_date", value:"2022-10-24 04:53:32 +0000 (Mon, 24 Oct 2022)");
  script_version("2022-10-24T04:53:32+0000");
  script_tag(name:"last_modification", value:"2022-10-24 04:53:32 +0000 (Mon, 24 Oct 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 14:06:00 +0000 (Tue, 18 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0379)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0379");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0379.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30969");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.66");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.67");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.68");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.69");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.70");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.71");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.72");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.73");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.74");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2022-0379 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on upstream 5.15.74 and fixes at least the
following security issues:

A flaw was found in the Linux kernel. The existing KVM SEV API has a
vulnerability that allows a non-root (host) user-level application to
crash the host kernel by creating a confidential guest VM instance in
AMD CPU that supports Secure Encrypted Virtualization (SEV)
(CVE-2022-0171).

A flaw was found in vDPA with VDUSE backend. There are currently no checks
in VDUSE kernel driver to ensure the size of the device config space is in
line with the features advertised by the VDUSE userspace application. In
case of a mismatch, Virtio drivers config read helpers do not initialize
the memory indirectly passed to vduse_vdpa_get_config() returning
uninitialized memory from the stack. This could cause undefined behavior or
data leaks in Virtio drivers (CVE-2022-2308).

An issue was found in the Linux kernel in nf_conntrack_irc where the
message handling can be confused and incorrectly matches the message.
A firewall may be able to be bypassed when users are using unencrypted
IRC with nf_conntrack_irc configured (CVE-2022-2663).

A flaw in the i740 driver. The Userspace program could pass any values
to the driver through ioctl() interface. The driver doesn't check the
value of 'pixclock', so it may cause a divide by zero error
(CVE-2022-3061).

A race condition flaw was found in the Linux kernel sound subsystem due
to improper locking. It could lead to a NULL pointer dereference while
handling the SNDCTL_DSP_SYNC ioctl. A privileged local user (root or
member of the audio group) could use this flaw to crash the system,
resulting in a denial of service condition (CVE-2022-3303).

A flaw was found in the Linux kernel networking code. A use-after-free
was found in the way the sch_sfb enqueue function used the socket buffer
(SKB) cb field after the same SKB had been enqueued (and freed) into a
child qdisc. This flaw allows a local, unprivileged user to crash the
system, causing a denial of service (CVE-2022-3586).

In binder_inc_ref_for_node of binder.c, there is a possible way to corrupt
memory due to a use after free. This could lead to local escalation of
privilege with no additional execution privileges needed. User interaction
is not needed for exploitation (CVE-2022-20421).

An issue was discovered in the Linux kernel before 5.19. In pxa3xx_gcu_write
in drivers/video/fbdev/pxa3xx-gcu.c, the count parameter has a type conflict
of size_t versus int, causing an integer overflow and bypassing the size
check. After that, because it is used as the third argument to
copy_from_user(), a heap overflow may occur (CVE-2022-39842).

An issue was discovered in the Linux kernel through 5.19.8.
drivers/firmware/efi/capsule-loader.c has a race condition with a resultant
use-after-free (CVE-2022-40307).

drivers/scsi/stex.c in the Linux kernel through 5.19.9 allows local users
to obtain sensitive ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.15.74-1.mga8", rpm:"kernel-desktop-5.15.74-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.15.74-1.mga8", rpm:"kernel-desktop-devel-5.15.74-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.15.74-1.mga8", rpm:"kernel-desktop586-5.15.74-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.15.74-1.mga8", rpm:"kernel-desktop586-devel-5.15.74-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.15.74-1.mga8", rpm:"kernel-server-5.15.74-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.15.74-1.mga8", rpm:"kernel-server-devel-5.15.74-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.15.74-1.mga8", rpm:"kernel-source-5.15.74-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.1.38~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.21~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.15.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.74-desktop-1.mga8", rpm:"virtualbox-kernel-5.15.74-desktop-1.mga8~6.1.38~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.74-server-1.mga8", rpm:"virtualbox-kernel-5.15.74-server-1.mga8~6.1.38~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.1.38~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.1.38~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.74-desktop-1.mga8", rpm:"xtables-addons-kernel-5.15.74-desktop-1.mga8~3.21~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.74-desktop586-1.mga8", rpm:"xtables-addons-kernel-5.15.74-desktop586-1.mga8~3.21~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.74-server-1.mga8", rpm:"xtables-addons-kernel-5.15.74-server-1.mga8~3.21~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.21~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.21~1.6.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.21~1.6.mga8", rls:"MAGEIA8"))) {
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
