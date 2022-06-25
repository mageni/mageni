# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1452");
  script_version("2020-04-16T05:54:57+0000");
  script_cve_id("CVE-2014-3180", "CVE-2017-18549", "CVE-2017-18550", "CVE-2017-18551", "CVE-2017-18595", "CVE-2018-1000026", "CVE-2018-5803", "CVE-2019-10220", "CVE-2019-11833", "CVE-2019-12382", "CVE-2019-12456", "CVE-2019-12819", "CVE-2019-15090", "CVE-2019-15212", "CVE-2019-15216", "CVE-2019-15916", "CVE-2019-15924", "CVE-2019-16233", "CVE-2019-18806", "CVE-2019-19447", "CVE-2019-19537", "CVE-2019-19965", "CVE-2019-20054", "CVE-2019-3874");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-04-16 10:29:54 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-16 05:54:57 +0000 (Thu, 16 Apr 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2020-1452)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.2\.2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1452");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2020-1452 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel 5.0.21, mounting a crafted ext4 filesystem image, performing some operations, and unmounting can lead to a use-after-free in ext4_put_super in fs/ext4/super.c, related to dump_orphan_list in fs/ext4/super.c.(CVE-2019-19447)

This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2019-10220)

** DISPUTED ** In kernel/compat.c in the Linux kernel before 3.17, as used in Google Chrome OS and other products, there is a possible out-of-bounds read. restart_syscall uses uninitialized data when restarting compat_sys_nanosleep. NOTE: this is disputed because the code path is unreachable.(CVE-2014-3180)

In the Linux kernel before 5.0.6, there is a NULL pointer dereference in drop_sysctl_table() in fs/proc/proc_sysctl.c, related to put_links, aka CID-23da9588037e(CVE-2019-20054)

pointer dereference in drivers/scsi/libsas/sas_discover.c because of mishandling of port disconnection during discovery, related to a PHY down race condition, aka CID-f70267f379b5.(CVE-2019-19965)'

In the Linux kernel before 5.2.10, there is a race condition bug that can be caused by a malicious USB device in the USB character device driver layer, aka CID-303911cfc5b9. This affects drivers/usb/core/file.c.(CVE-2019-19537)

Linux Linux kernel version at least v4.8 onwards, probably well before contains a Insufficient input validation vulnerability in bnx2x network card driver that can result in DoS: Network card firmware assertion takes card off-line. This attack appear to be exploitable via An attacker on a must pass a very large, specially crafted packet to the bnx2x card. This can be done from an untrusted guest VM..(CVE-2018-1000026)

drivers/scsi/qla2xxx/qla_os.c in the Linux kernel 5.2.14 does not check the alloc_workqueue return value, leading to a NULL pointer dereference.(CVE-2019-16233)

The SCTP socket buffer used by a userspace application is not accounted by the cgroups subsystem. An attacker can use this flaw to cause a denial of service attack. Kernel 3.10.x and 4.18.x branches are believed to be vulnerable.(CVE-2019-3874)

fs/ext4/extents.c in the Linux kernel through 5.1.2 does not zero out the unused memory region in the extent tree block, which might allow local users to obtain sensitive information by reading uninitialized data in the filesystem.(CVE-2019-11833)

A memory leak in the ql_alloc_large_buffers() function in drivers/net/ethernet/qlogic/qla3xxx.c in the Linux kernel before 5.3.5 allows local users to  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_72", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_72", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_72", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_72", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_72", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_72", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_72", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_72", rls:"EULEROSVIRT-3.0.2.2"))) {
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