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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1342");
  script_version("2020-04-01T13:54:05+0000");
  script_cve_id("CVE-2019-11135", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-19332", "CVE-2019-19338", "CVE-2019-19922", "CVE-2019-19947", "CVE-2019-20095", "CVE-2019-20096", "CVE-2019-3016", "CVE-2019-5108", "CVE-2020-8428", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-9383");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-04-02 09:54:57 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-01 13:54:05 +0000 (Wed, 01 Apr 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2020-1342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.6\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1342");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2020-1342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow was discovered in the Linux kernel's Marvell WiFi chip driver. The flaw could occur when the station attempts a connection negotiation during the handling of the remote devices country settings. This could allow the remote device to cause a denial of service (system crash) or possibly execute arbitrary code.(CVE-2019-14895)

A flaw was found in the fix for CVE-2019-11135, the way Intel CPUs handle speculative execution of instructions when a TSX Asynchronous Abort (TAA) error occurs. When a guest is running on a host CPU affected by the TAA flaw (TAA_NO=0), but is not affected by the MDS issue (MDS_NO=1), the guest was to clear the affected buffers by using a VERW instruction mechanism. But when the MDS_NO=1 bit was exported to the guests, the guests did not use the VERW mechanism to clear the affected buffers. This issue affects guests running on Cascade Lake CPUs and requires that host has 'TSX' enabled. Confidentiality of data is the highest threat associated with this vulnerability.(CVE-2019-19338)

A flaw was found in the way Intel CPUs handle speculative execution of instructions when the TSX Asynchronous Abort (TAA) error occurs. A local authenticated attacker with the ability to monitor execution times could infer the TSX memory state by comparing abort execution times. This could allow information disclosure via this observed side-channel for any TSX transaction being executed while an attacker is able to observe abort timing. Intel's Transactional Synchronisation Extensions (TSX) are set of instructions which enable transactional memory support to improve performance of the multi-threaded applications, in the lock-protected critical sections. The CPU executes instructions in the critical-sections as transactions, while ensuring their atomic state. When such transaction execution is unsuccessful, the processor cannot ensure atomic updates to the transaction memory, so the processor rolls back or aborts such transaction execution. While TSX Asynchronous Abort (TAA) is pending, CPU may continue to read data from architectural buffers and pass it to the dependent speculative operations. This may cause information leakage via speculative side-channel means, which is quite similar to the Microarchitectural Data Sampling (MDS) issue.(CVE-2019-11135)

An out-of-bounds memory write issue was found in the way the Linux kernel's KVM hypervisor handled the 'KVM_GET_EMULATED_CPUID' ioctl(2) request to get CPUID features emulated by the KVM hypervisor. A user or process able to access the '/dev/kvm' device could use this flaw to crash the s ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h697.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h697.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h697.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h697.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h697.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.36~vhulk1907.1.0.h697.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~vhulk1907.1.0.h697.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~vhulk1907.1.0.h697.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.36~vhulk1907.1.0.h697.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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