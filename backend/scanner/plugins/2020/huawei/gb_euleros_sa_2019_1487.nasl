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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1487");
  script_version("2020-01-23T11:54:17+0000");
  script_cve_id("CVE-2015-1805", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2666", "CVE-2015-2672", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-2925", "CVE-2015-3212", "CVE-2015-3288", "CVE-2015-3290", "CVE-2015-3291", "CVE-2015-3331", "CVE-2015-3339", "CVE-2015-3636", "CVE-2015-4167", "CVE-2015-4170", "CVE-2015-4177", "CVE-2015-4692", "CVE-2015-4700", "CVE-2015-5156");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:54:17 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:54:17 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1487)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1487");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1487 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the Linux kernel's implementation of vectored pipe read and write functionality did not take into account the I/O vectors that were already processed when retrying after a failed atomic access operation, potentially resulting in memory corruption due to an I/O vector array overrun. A local, unprivileged user could use this flaw to crash the system or, potentially, escalate their privileges on the system.(CVE-2015-1805)

net/llc/sysctl_net_llc.c in the Linux kernel before 3.19 uses an incorrect data type in a sysctl table, which allows local users to obtain potentially sensitive information from kernel memory or possibly have unspecified other impact by accessing a sysctl entry.(CVE-2015-2041)

net/rds/sysctl.c in the Linux kernel before 3.19 uses an incorrect data type in a sysctl table, which allows local users to obtain potentially sensitive information from kernel memory or possibly have unspecified other impact by accessing a sysctl entry.(CVE-2015-2042)

Xen 3.3.x through 4.5.x and the Linux kernel through 3.19.1 do not properly restrict access to PCI command registers, which might allow local guest OS users to cause a denial of service (non-maskable interrupt and host crash) by disabling the (1) memory or (2) I/O decoding for a PCI Express device and then accessing the device, which triggers an Unsupported Request (UR) response.(CVE-2015-2150)

A stack-based buffer overflow flaw was found in the Linux kernel's early load microcode functionality. On a system with UEFI Secure Boot enabled, a local, privileged user could use this flaw to increase their privileges to the kernel (ring0) level, bypassing intended restrictions in place.(CVE-2015-2666)

The xsave/xrstor implementation in arch/x86/include/asm/xsave.h in the Linux kernel before 3.19.2 creates certain .altinstr_replacement pointers and consequently does not provide any protection against instruction faulting, which allows local users to cause a denial of service (panic) by triggering a fault, as demonstrated by an unaligned memory operand or a non-canonical address memory operand.(CVE-2015-2672)

A flaw was found in the way the Linux kernel's 32-bit emulation implementation handled forking or closing of a task with an 'int80' entry. A local user could potentially use this flaw to escalate their privileges on the system.(CVE-2015-2830)

It was found that the Linux kernel's TCP/IP protocol suite implementation for IPv6 allowed the Hop Limit value to be set to a smaller value than the default one. An attacker on a local network could use this flaw to prevent systems on that network from sending or r ...

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