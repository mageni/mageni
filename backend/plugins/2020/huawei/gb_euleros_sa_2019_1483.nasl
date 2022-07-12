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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1483");
  script_version("2020-01-23T11:52:55+0000");
  script_cve_id("CVE-2014-7841", "CVE-2014-7842", "CVE-2014-7970", "CVE-2014-7975", "CVE-2014-8086", "CVE-2014-8160", "CVE-2014-8172", "CVE-2014-8173", "CVE-2014-8369", "CVE-2014-8480", "CVE-2014-8481", "CVE-2014-8559", "CVE-2014-8709", "CVE-2014-8884", "CVE-2014-9090", "CVE-2014-9322", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:52:55 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:52:55 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1483)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1483");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1483 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way the Linux kernel's SCTP implementation validated INIT chunks when performing Address Configuration Change (ASCONF). A remote attacker could use this flaw to crash the system by sending a specially crafted SCTP packet to trigger a NULL pointer dereference on the system.(CVE-2014-7841)

It was found that reporting emulation failures to user space could lead to either a local (CVE-2014-7842) or a L2-L1 (CVE-2010-5313) denial of service. In the case of a local denial of service, an attacker must have access to the MMIO area or be able to access an I/O port. Please note that on certain systems, HPET is mapped to userspace as part of vdso (vvar) and thus an unprivileged user may generate MMIO transactions (and enter the emulator) this way.(CVE-2014-7842)

The pivot_root implementation in fs/namespace.c in the Linux kernel through 3.17 does not properly interact with certain locations of a chroot directory, which allows local users to cause a denial of service (mount-tree loop) via . (dot) values in both arguments to the pivot_root system call.(CVE-2014-7970)

The do_umount function in fs/namespace.c in the Linux kernel through 3.17 does not require the CAP_SYS_ADMIN capability for do_remount_sb calls that change the root filesystem to read-only, which allows local users to cause a denial of service (loss of writability) by making certain unshare system calls, clearing the / MNT_LOCKED flag, and making an MNT_FORCE umount system call.(CVE-2014-7975)

A race condition flaw was found in the Linux kernel's ext4 file system implementation that allowed a local, unprivileged user to crash the system by simultaneously writing to a file and toggling the O_DIRECT flag using fcntl(F_SETFL) on that file.(CVE-2014-8086)

A flaw was found in the way the Linux kernel's netfilter subsystem handled generic protocol tracking. As demonstrated in the Stream Control Transmission Protocol (SCTP) case, a remote attacker could use this flaw to bypass intended iptables rule restrictions when the associated connection tracking module was not loaded on the system.(CVE-2014-8160)

It was found that due to excessive files_lock locking, a soft lockup could be triggered in the Linux kernel when performing asynchronous I/O operations. A local, unprivileged user could use this flaw to crash the system.(CVE-2014-8172)

A NULL pointer dereference flaw was found in the way the Linux kernel's madvise MADV_WILLNEED functionality handled page table locking. A local, unprivileged user could use this flaw to crash the system.(CVE-2014-8173)

It was found that the fix for CVE-2014-3601 was incom ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
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