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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0152");
  script_cve_id("CVE-2020-25639", "CVE-2020-27170", "CVE-2020-27171", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-28038", "CVE-2021-28039", "CVE-2021-28375");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-09 09:15:00 +0000 (Fri, 09 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0152)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0152");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0152.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28611");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28596");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.20");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.21");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.22");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.23");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.24");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.25");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus, kernel-linus' package(s) announced via the MGASA-2021-0152 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.10.25 and fixes at least the
following security issues:

A NULL pointer dereference flaw was found in the Linux kernel's GPU Nouveau
driver functionality in versions prior to 5.12-rc1 in the way the user calls
ioctl DRM_IOCTL_NOUVEAU_CHANNEL_ALLOC. This flaw allows a local user to
crash the system. (CVE-2020-25639).

Unprivileged BPF programs running on affected systems can bypass the
protection and execute speculatively out-of-bounds loads from any location
within the kernel memory. This can be abused to extract contents of kernel
memory via side-channel (CVE-2020-27170).

Unprivileged BPF programs running on affected 64-bit systems can exploit
this to execute speculatively out-of-bounds loads from 4GB window within
the kernel memory. This can be abused to extract contents of kernel memory
via side-channel (CVE-2020-27171).

An issue was discovered in the Linux kernel through 5.11.3. A kernel pointer
leak can be used to determine the address of the iscsi_transport structure.
When an iSCSI transport is registered with the iSCSI subsystem, the
transport's handle is available to unprivileged users via the sysfs file
system, at /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When read, the
show_transport_handle function (in drivers/scsi/scsi_transport_iscsi.c) is
called, which leaks the handle. This handle is actually the pointer to an
iscsi_transport struct in the kernel module's global variables
(CVE-2021-27363).

An issue was discovered in the Linux kernel through 5.11.3. drivers/scsi/
scsi_transport_iscsi.c is adversely affected by the ability of an
unprivileged user to craft Netlink messages (CVE-2021-27364).

An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI
data structures do not have appropriate length constraints or checks, and
can exceed the PAGE_SIZE value. An unprivileged user can send a Netlink
message that is associated with iSCSI, and has a length up to the maximum
length of a Netlink message (CVE-2021-27365).

An issue was discovered in the Linux kernel through 5.11.3, as used with
Xen PV. A certain part of the netback driver lacks necessary treatment of
errors such as failed memory allocations (as a result of changes to the
handling of grant mapping errors). A host OS denial of service may occur
during misbehavior of a networking frontend driver. NOTE: this issue
exists because of an incomplete fix for CVE-2021-26931.
(CVE-2021-28038 / XSA-367)

An issue was discovered in the Linux kernel 5.9.x through 5.11.3, as used
with Xen. In some less-common configurations, an x86 PV guest OS user can
crash a Dom0 or driver domain via a large amount of I/O activity. The
issue relates to misuse of guest physical addresses when a configuration
has CONFIG_XEN_UNPOPULATED_ALLOC but not CONFIG_XEN_BALLOON_MEMORY_HOTPLUG.
(CVE-2021-28039 / XSA-369)

An issue was discovered in the Linux kernel through ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-linus, kernel-linus' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.10.25-1.mga7", rpm:"kernel-linus-5.10.25-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.10.25~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.10.25-1.mga7", rpm:"kernel-linus-devel-5.10.25-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.10.25~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.10.25~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.10.25~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.10.25-1.mga7", rpm:"kernel-linus-source-5.10.25-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.10.25~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.10.25-1.mga8", rpm:"kernel-linus-5.10.25-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.10.25~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.10.25-1.mga8", rpm:"kernel-linus-devel-5.10.25-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.10.25~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.10.25~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.10.25~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.10.25-1.mga8", rpm:"kernel-linus-source-5.10.25-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.10.25~1.mga8", rls:"MAGEIA8"))) {
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
