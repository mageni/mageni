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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1480");
  script_version("2020-01-23T11:51:53+0000");
  script_cve_id("CVE-2014-3153", "CVE-2014-3181", "CVE-2014-3182", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3534", "CVE-2014-3601", "CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3631", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-3690", "CVE-2014-3917", "CVE-2014-3940", "CVE-2014-4014", "CVE-2014-4027");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:51:53 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:51:53 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1480)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1480");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1480 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way the Linux kernel's futex subsystem handled the requeuing of certain Priority Inheritance (PI) futexes. A local, unprivileged user could use this flaw to escalate their privileges on the system.(CVE-2014-3153)

An out-of-bounds write flaw was found in the way the Apple Magic Mouse/Trackpad multi-touch driver handled Human Interface Device (HID) reports with an invalid size. An attacker with physical access to the system could use this flaw to crash the system or, potentially, escalate their privileges on the system.(CVE-2014-3181)

An out-of-bounds read flaw was found in the way the Logitech Unifying receiver driver handled HID reports with an invalid device_index value. An attacker with physical access to the system could use this flaw to crash the system or, potentially, escalate their privileges on the system.(CVE-2014-3182)

Multiple out-of-bounds write flaws were found in the way the Cherry Cymotion keyboard driver, KYE/Genius device drivers, Logitech device drivers, Monterey Genius KB29E keyboard driver, Petalynx Maxter remote control driver, and Sunplus wireless desktop driver handled HID reports with an invalid report descriptor size. An attacker with physical access to the system could use either of these flaws to write data past an allocated memory buffer.(CVE-2014-3184)

A memory corruption flaw was found in the way the USB ConnectTech WhiteHEAT serial driver processed completion commands sent via USB Request Blocks buffers. An attacker with physical access to the system could use this flaw to crash the system or, potentially, escalate their privileges on the system.(CVE-2014-3185)

It was found that Linux kernel's ptrace subsystem did not properly sanitize the address-space-control bits when the program-status word (PSW) was being set. On IBM S/390 systems, a local, unprivileged user could use this flaw to set address-space-control bits to the kernel space, and thus gain read and write access to kernel memory.(CVE-2014-3534)

A flaw was found in the way the Linux kernel's kvm_iommu_map_pages() function handled IOMMU mapping failures. A privileged user in a guest with an assigned host device could use this flaw to crash the host.(CVE-2014-3601)

It was found that KVM's Write to Model Specific Register (WRMSR) instruction emulation would write non-canonical values passed in by the guest to certain MSRs in the host's context. A privileged guest user could use this flaw to crash the host.(CVE-2014-3610)

A race condition flaw was found in the way the Linux kernel's KVM subsystem handled PIT (Programmable Interval Timer) emulation. A guest us ...

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