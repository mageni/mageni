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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1473");
  script_version("2020-01-23T11:49:27+0000");
  script_cve_id("CVE-2013-1059", "CVE-2013-2140", "CVE-2013-2164", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-2929", "CVE-2013-2930", "CVE-2013-4125", "CVE-2013-4127", "CVE-2013-4162", "CVE-2013-4163", "CVE-2013-4205", "CVE-2013-4247", "CVE-2013-4270", "CVE-2013-4299", "CVE-2013-4300", "CVE-2013-4312", "CVE-2013-4343", "CVE-2013-4345");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:49:27 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:49:27 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1473)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1473");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1473 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"net/ceph/auth_none.c in the Linux kernel through 3.10 allows remote attackers to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via an auth_reply message that triggers an attempted build_request operation.(CVE-2013-1059)

The dispatch_discard_io function in drivers/block/xen-blkback/blkback.c in the Xen blkback implementation in the Linux kernel before 3.10.5 allows guest OS users to cause a denial of service (data loss) via filesystem write operations on a read-only disk that supports the (1) BLKIF_OP_DISCARD (aka discard or TRIM) or (2) SCSI UNMAP feature.(CVE-2013-2140)

The mmc_ioctl_cdrom_read_data function in drivers/cdrom/cdrom.c in the Linux kernel through 3.10 allows local users to obtain sensitive information from kernel memory via a read operation on a malfunctioning CD-ROM drive.(CVE-2013-2164)

Multiple array index errors in drivers/hid/hid-core.c in the Human Interface Device (HID) subsystem in the Linux kernel through 3.11 allow physically proximate attackers to execute arbitrary code or cause a denial of service (heap memory corruption) via a crafted device that provides an invalid Report ID.(CVE-2013-2888)

drivers/hid/hid-zpff.c in the Human Interface Device (HID) subsystem in the Linux kernel through 3.11, when CONFIG_HID_ZEROPLUS is enabled, allows physically proximate attackers to cause a denial of service (heap-based out-of-bounds write) via a crafted device.(CVE-2013-2889)

drivers/hid/hid-pl.c in the Human Interface Device (HID) subsystem in the Linux kernel through 3.11, when CONFIG_HID_PANTHERLORD is enabled, allows physically proximate attackers to cause a denial of service (heap-based out-of-bounds write) via a crafted device.(CVE-2013-2892)

A flaw was found in the way the get_dumpable() function return value was interpreted in the ptrace subsystem of the Linux kernel. When 'fs.suid_dumpable' was set to 2, a local, unprivileged local user could use this flaw to bypass intended ptrace restrictions and obtain potentially sensitive information.(CVE-2013-2929)

The perf_trace_event_perm function in kernel/trace/trace_event_perf.c in the Linux kernel before 3.12.2 does not properly restrict access to the perf subsystem, which allows local users to enable function tracing via a crafted application.(CVE-2013-2930)

The fib6_add_rt2node function in net/ipv6/ip6_fib.c in the IPv6 stack in the Linux kernel through 3.10.1 does not properly handle Router Advertisement (RA) messages in certain circumstances involving three routes that initially qualified for membership in an ECMP route set until  ...

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