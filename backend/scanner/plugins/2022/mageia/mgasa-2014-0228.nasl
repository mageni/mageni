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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0228");
  script_cve_id("CVE-2013-6885", "CVE-2014-0049", "CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0077", "CVE-2014-0155", "CVE-2014-0196", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2851");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-26 13:50:00 +0000 (Wed, 26 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0228)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0228");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0228.html");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.40");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.39");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.38");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.37");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.36");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.35");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.34");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.33");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.32");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.31");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.30");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.29");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13397");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia-current, kmod-nvidia173, kmod-nvidia304, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2014-0228 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated kernel provides upstream 3.10.40 kernel and fixes the
following security issues:

The microcode on AMD 16h 00h through 0Fh processors does not properly
handle the interaction between locked instructions and write-combined
memory types, which allows local users to cause a denial of service
(system hang) via a crafted application, aka the errata 793 issue.
(CVE-2013-6885)

Buffer overflow in the complete_emulated_mmio function in arch/x86/kvm/
x86.c in the Linux kernel before 3.13.6 allows guest OS users to execute
arbitrary code on the host OS by leveraging a loop that triggers an
invalid memory copy affecting certain cancel_work_item data.
(CVE-2014-0049)

The get_rx_bufs function in drivers/vhost/net.c in the vhost-net subsystem
in the Linux kernel package before 2.6.32-431.11.2 on Red Hat Enterprise
Linux (RHEL) 6 does not properly handle vhost_get_vq_desc errors, which
allows guest OS users to cause a denial of service (host OS crash) via
unspecified vectors. (CVE-2014-0055)

The cifs_iovec_write function in fs/cifs/file.c in the Linux kernel through
3.13.5 does not properly handle uncached write operations that copy fewer
than the requested number of bytes, which allows local users to obtain
sensitive information from kernel memory, cause a denial of service
(memory corruption and system crash), or possibly gain privileges via a
writev system call with a crafted pointer. (CVE-2014-0069)

drivers/vhost/net.c in the Linux kernel before 3.13.10, when mergeable
buffers are disabled, does not properly validate packet lengths, which
allows guest OS users to cause a denial of service (memory corruption and
host OS crash) or possibly gain privileges on the host OS via crafted
packets, related to the handle_rx and get_rx_bufs functions.
(CVE-2014-0077)

The ioapic_deliver function in virt/kvm/ioapic.c in the Linux kernel
through 3.14.1 does not properly validate the kvm_irq_delivery_to_apic
return value, which allows guest OS users to cause a denial of service
(host OS crash) via a crafted entry in the redirection table of an I/O
APIC. NOTE: the affected code was moved to the ioapic_service function
before the vulnerability was announced. (CVE-2014-0155)

The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel
through 3.14.3 does not properly manage tty driver access in the
'LECHO & !OPOST' case, which allows local users to cause a denial of
service (memory corruption and system crash) or gain privileges by
triggering a race condition involving read and write operations with
long strings. (CVE-2014-0196)

The raw_cmd_copyin function in drivers/block/floppy.c in the Linux
kernel through 3.14.3 does not properly handle error conditions during
processing of an FDRAWCMD ioctl call, which allows local users to trigger
kfree operations and gain privileges by leveraging write access to a
/dev/fd device. (CVE-2014-1737)

The raw_cmd_copyout function in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia-current, kmod-nvidia173, kmod-nvidia304, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.40-desktop-1.mga3", rpm:"broadcom-wl-kernel-3.10.40-desktop-1.mga3~6.30.223.141~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.40-desktop586-1.mga3", rpm:"broadcom-wl-kernel-3.10.40-desktop586-1.mga3~6.30.223.141~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.40-server-1.mga3", rpm:"broadcom-wl-kernel-3.10.40-server-1.mga3~6.30.223.141~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop-latest", rpm:"broadcom-wl-kernel-desktop-latest~6.30.223.141~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop586-latest", rpm:"broadcom-wl-kernel-desktop586-latest~6.30.223.141~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-server-latest", rpm:"broadcom-wl-kernel-server-latest~6.30.223.141~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.40-desktop-1.mga3", rpm:"fglrx-kernel-3.10.40-desktop-1.mga3~13.251~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.40-desktop586-1.mga3", rpm:"fglrx-kernel-3.10.40-desktop586-1.mga3~13.251~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.40-server-1.mga3", rpm:"fglrx-kernel-3.10.40-server-1.mga3~13.251~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~13.251~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~13.251~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~13.251~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-3.10.40-1.mga3", rpm:"kernel-desktop-3.10.40-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-3.10.40-1.mga3", rpm:"kernel-desktop-devel-3.10.40-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-3.10.40-1.mga3", rpm:"kernel-desktop586-3.10.40-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-3.10.40-1.mga3", rpm:"kernel-desktop586-devel-3.10.40-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-3.10.40-1.mga3", rpm:"kernel-server-3.10.40-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-3.10.40-1.mga3", rpm:"kernel-server-devel-3.10.40-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-3.10.40-1.mga3", rpm:"kernel-source-3.10.40-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-broadcom-wl", rpm:"kmod-broadcom-wl~6.30.223.141~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-fglrx", rpm:"kmod-fglrx~13.251~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~319.60~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia173", rpm:"kmod-nvidia173~173.14.38~30.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia304", rpm:"kmod-nvidia304~304.108~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.3~15.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.40-desktop-1.mga3", rpm:"nvidia-current-kernel-3.10.40-desktop-1.mga3~319.60~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.40-desktop586-1.mga3", rpm:"nvidia-current-kernel-3.10.40-desktop586-1.mga3~319.60~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.40-server-1.mga3", rpm:"nvidia-current-kernel-3.10.40-server-1.mga3~319.60~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~319.60~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~319.60~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~319.60~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.40-desktop-1.mga3", rpm:"nvidia173-kernel-3.10.40-desktop-1.mga3~173.14.38~30.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.40-desktop586-1.mga3", rpm:"nvidia173-kernel-3.10.40-desktop586-1.mga3~173.14.38~30.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.40-server-1.mga3", rpm:"nvidia173-kernel-3.10.40-server-1.mga3~173.14.38~30.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop-latest", rpm:"nvidia173-kernel-desktop-latest~173.14.38~30.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop586-latest", rpm:"nvidia173-kernel-desktop586-latest~173.14.38~30.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-server-latest", rpm:"nvidia173-kernel-server-latest~173.14.38~30.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.40-desktop-1.mga3", rpm:"nvidia304-kernel-3.10.40-desktop-1.mga3~304.108~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.40-desktop586-1.mga3", rpm:"nvidia304-kernel-3.10.40-desktop586-1.mga3~304.108~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.40-server-1.mga3", rpm:"nvidia304-kernel-3.10.40-server-1.mga3~304.108~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop-latest", rpm:"nvidia304-kernel-desktop-latest~304.108~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop586-latest", rpm:"nvidia304-kernel-desktop586-latest~304.108~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-server-latest", rpm:"nvidia304-kernel-server-latest~304.108~15.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.40-desktop-1.mga3", rpm:"vboxadditions-kernel-3.10.40-desktop-1.mga3~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.40-desktop586-1.mga3", rpm:"vboxadditions-kernel-3.10.40-desktop586-1.mga3~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.40-server-1.mga3", rpm:"vboxadditions-kernel-3.10.40-server-1.mga3~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.40-desktop-1.mga3", rpm:"virtualbox-kernel-3.10.40-desktop-1.mga3~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.40-desktop586-1.mga3", rpm:"virtualbox-kernel-3.10.40-desktop586-1.mga3~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.40-server-1.mga3", rpm:"virtualbox-kernel-3.10.40-server-1.mga3~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~4.3.10~5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.40-desktop-1.mga3", rpm:"xtables-addons-kernel-3.10.40-desktop-1.mga3~2.3~15.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.40-desktop586-1.mga3", rpm:"xtables-addons-kernel-3.10.40-desktop586-1.mga3~2.3~15.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.40-server-1.mga3", rpm:"xtables-addons-kernel-3.10.40-server-1.mga3~2.3~15.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~2.3~15.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~2.3~15.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~2.3~15.mga3", rls:"MAGEIA3"))) {
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
