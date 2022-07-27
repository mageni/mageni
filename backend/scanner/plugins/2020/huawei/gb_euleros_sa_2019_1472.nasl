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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1472");
  script_version("2020-01-23T11:49:09+0000");
  script_cve_id("CVE-2013-2892", "CVE-2014-2568", "CVE-2014-7843", "CVE-2014-9420", "CVE-2014-9529", "CVE-2014-9730", "CVE-2016-2070", "CVE-2016-2383", "CVE-2016-3134", "CVE-2016-4568", "CVE-2016-6327", "CVE-2016-7915", "CVE-2016-9754", "CVE-2017-16525", "CVE-2017-18079", "CVE-2017-18204", "CVE-2017-7261", "CVE-2017-9605", "CVE-2018-1094", "CVE-2018-16276");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:49:09 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:49:09 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1472)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1472");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1472 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The hid_input_field() function in 'drivers/hid/hid-core.c' in the Linux kernel before 4.6 allows physically proximate attackers to obtain sensitive information from kernel memory or cause a denial of service (out-of-bounds read) by connecting a device.(CVE-2016-7915

The Linux kernel, before version 4.14.2, is vulnerable to a deadlock caused by fs/ocfs2/file.c:ocfs2_setattr(), as the function does not wait for DIO requests before locking the inode. This can be exploited by local users to cause a subsequent denial of service.(CVE-2017-18204

The vmw_gb_surface_define_ioctl function (accessible via DRM_IOCTL_VMW_GB_SURFACE_CREATE) in drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux kernel through 4.11.4 defines a backup_handle variable but does not give it an initial value. If one attempts to create a GB surface, with a previously allocated DMA buffer to be used as a backup buffer, the backup_handle variable does not get written to and is then later returned to user space, allowing local users to obtain sensitive information from uninitialized kernel memory via a crafted ioctl call.(CVE-2017-9605

Use-after-free vulnerability in the nfqnl_zcopy function in net/netfilter/nfnetlink_queue_core.c in the Linux kernel through 3.13.6 allows attackers to obtain sensitive information from kernel memory by leveraging the absence of a certain orphaning operation. NOTE: the affected code was moved to the skb_zerocopy function in net/core/skbuff.c before the vulnerability was announced.(CVE-2014-2568

It was found that the Linux kernel's ISO file system implementation did not correctly limit the traversal of Rock Ridge extension Continuation Entries (CE). An attacker with physical access to the system could use this flaw to trigger an infinite loop in the kernel, resulting in a denial of service.(CVE-2014-9420

An integer overflow vulnerability was found in the ring_buffer_resize() calculations in which a privileged user can adjust the size of the ringbuffer message size. These calculations can create an issue where the kernel memory allocator will not allocate the correct count of pages yet expect them to be usable. This can lead to the ftrace() output to appear to corrupt kernel memory and possibly be used for privileged escalation or more likely kernel panic.(CVE-2016-9754

A symlink size validation was missing in Linux kernels built with UDF file system (CONFIG_UDF_FS) support, allowing the corruption of kernel memory. An attacker able to mount a corrupted/malicious UDF file system image could cause the kernel to crash.(CVE-2014-9730

In was found that in the Linux kernel ...

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