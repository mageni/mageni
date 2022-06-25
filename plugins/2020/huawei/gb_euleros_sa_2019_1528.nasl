# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1528");
  script_version("2020-01-23T12:05:30+0000");
  script_cve_id("CVE-2014-2038", "CVE-2014-3917", "CVE-2014-4508", "CVE-2014-8480", "CVE-2015-3339", "CVE-2015-4001", "CVE-2015-4002", "CVE-2015-8962", "CVE-2016-1576", "CVE-2016-2085", "CVE-2016-4997", "CVE-2016-7913", "CVE-2016-7916", "CVE-2016-9777", "CVE-2017-15115", "CVE-2017-15265", "CVE-2017-16526", "CVE-2017-17448", "CVE-2017-7482", "CVE-2018-8043");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 12:05:30 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:05:30 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1528)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1528");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1528 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds memory access flaw was found in the Linux kernel's system call auditing implementation. On a system with existing audit rules defined, a local, unprivileged user could use this flaw to leak kernel memory to user space or, potentially, crash the system.(CVE-2014-3917

The net/netfilter/nfnetlink_cthelper.c function in the Linux kernel through 4.14.4 does not require the CAP_NET_ADMIN capability for new, get, and del operations. This allows local users to bypass intended access restrictions because the nfnl_cthelper_list data structure is shared across all net namespaces.(CVE-2017-17448

A race condition flaw was found between the chown and execve system calls. When changing the owner of a setuid user binary to root, the race condition could momentarily make the binary setuid root. A local, unprivileged user could potentially use this flaw to escalate their privileges on the system.(CVE-2015-3339

Keberos 5 tickets being decoded when using the RXRPC keys incorrectly assumes the size of a field. This could lead to the size-remaining variable wrapping and the data pointer going over the end of the buffer. This could possibly lead to memory corruption and possible privilege escalation.(CVE-2017-7482

The nfs_can_extend_write function in fs/nfs/write.c in the Linux kernel before 3.13.3 relies on a write delegation to extend a write operation without a certain up-to-date verification, which allows local users to obtain sensitive information from kernel memory in opportunistic circumstances by writing to a file in an NFS filesystem and then reading the same file.(CVE-2014-2038

KVM in the Linux kernel before 4.8.12, when I/O APIC is enabled, does not properly restrict the VCPU index, which allows guest OS users to gain host OS privileges or cause a denial of service (out-of-bounds array access and host OS crash) via a crafted interrupt request, related to arch/x86/kvm/ioapic.c and arch/x86/kvm/ioapic.h.(CVE-2016-9777

The instruction decoder in arch/x86/kvm/emulate.c in the KVM subsystem in the Linux kernel before 3.18-rc2 lacks intended decoder-table flags for certain RIP-relative instructions, which allows guest OS users to cause a denial of service (NULL pointer dereference and host OS crash) via a crafted application.(CVE-2014-8480

arch/x86/kernel/entry_32.S in the Linux kernel through 3.15.1 on 32-bit x86 platforms, when syscall auditing is enabled and the sep CPU feature flag is set, allows local users to cause a denial of service (OOPS and system crash) via an invalid syscall number, as demonstrated by number 1000.(CVE-2014-4508

The overlayfs impl ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.1.0.");

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

if(release == "EULEROSVIRTARM64-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);