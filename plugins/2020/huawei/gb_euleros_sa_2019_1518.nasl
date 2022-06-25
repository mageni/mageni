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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1518");
  script_version("2020-01-23T12:02:17+0000");
  script_cve_id("CVE-2013-2897", "CVE-2014-1739", "CVE-2014-3144", "CVE-2014-3153", "CVE-2014-3646", "CVE-2015-0239", "CVE-2015-1339", "CVE-2015-1350", "CVE-2015-3290", "CVE-2015-7885", "CVE-2015-8539", "CVE-2016-5412", "CVE-2016-8660", "CVE-2016-9083", "CVE-2016-9755", "CVE-2017-15127", "CVE-2017-2596", "CVE-2018-16597", "CVE-2018-16658", "CVE-2018-17972");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 12:02:17 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:02:17 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1518)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1518");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1518 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Linux kernel built with the KVM visualization support (CONFIG_KVM), with nested visualization(nVMX) feature enabled(nested=1), is vulnerable to host memory leakage issue. It could occur while emulating VMXON instruction in 'handle_vmon'. An L1 guest user could use this flaw to leak host memory potentially resulting in DoS.(CVE-2017-2596

The (1) BPF_S_ANC_NLATTR and (2) BPF_S_ANC_NLATTR_NEST extension implementations in the sk_run_filter function in net/core/filter.c in the Linux kernel through 3.14.3 do not check whether a certain length value is sufficiently large, which allows local users to cause a denial of service (integer underflow and system crash) via crafted BPF instructions. NOTE: the affected code was moved to the __skb_get_nlattr and __skb_get_nlattr_nest functions before the vulnerability was announced.(CVE-2014-3144

A flaw was found in the Linux kernel when freeing pages in hugetlbfs. This could trigger a local denial of service by crashing the kernel.(CVE-2017-15127

An issue was discovered in the Linux kernel before 4.8. Incorrect access checking in overlayfs mounts could be used by local attackers to modify or truncate files in the underlying filesystem.(CVE-2018-16597

Memory leak in the cuse_channel_release function in fs/fuse/cuse.c in the Linux kernel before 4.4 allows local users to cause a denial of service (memory consumption) or possibly have unspecified other impact by opening /dev/cuse many times.(CVE-2015-1339

A flaw was found in the way the Linux kernel's nested NMI handler and espfix64 functionalities interacted during NMI processing. A local, unprivileged user could use this flaw to crash the system or, potentially, escalate their privileges on the system.(CVE-2015-3290

Multiple array index errors in drivers/hid/hid-multitouch.c in the Human Interface Device (HID) subsystem in the Linux kernel through 3.11, when CONFIG_HID_MULTITOUCH is enabled, allow physically proximate attackers to cause a denial of service (heap memory corruption, or NULL pointer dereference and OOPS) via a crafted device.(CVE-2013-2897

A flaw was found in the way the Linux kernel's futex subsystem handled the requeuing of certain Priority Inheritance (PI) futexes. A local, unprivileged user could use this flaw to escalate their privileges on the system.(CVE-2014-3153

The XFS subsystem in the Linux kernel 4.4 and later allows local users to cause a denial of service (fdatasync() failure and system hang) by using the vfs syscall group in the 'trinity' program, as a result of a page lock order bug in the XFS seek hole/data implementation.(CVE-2016-8660

A flaw ...

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