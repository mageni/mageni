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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1499");
  script_version("2020-01-23T11:57:19+0000");
  script_cve_id("CVE-2017-12190", "CVE-2017-12192", "CVE-2017-12193", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-14489", "CVE-2017-14991", "CVE-2017-15102", "CVE-2017-15115", "CVE-2017-15129", "CVE-2017-15265", "CVE-2017-15274", "CVE-2017-15299", "CVE-2017-15649", "CVE-2017-16525", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16528", "CVE-2017-16529", "CVE-2017-16530", "CVE-2017-16531", "CVE-2017-16532");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:57:19 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:57:19 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1499)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1499");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1499 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that in the Linux kernel through v4.14-rc5, bio_map_user_iov() and bio_unmap_user() in 'block/bio.c' do unbalanced pages refcounting if IO vector has small consecutive buffers belonging to the same page. bio_add_pc_page() merges them into one, but the page reference is never dropped, causing a memory leak and possible system lockup due to out-of-memory condition.(CVE-2017-12190)

A vulnerability was found in the Key Management sub component of the Linux kernel, where when trying to issue a KEYTCL_READ on a negative key would lead to a NULL pointer dereference. A local attacker could use this flaw to crash the kernel.(CVE-2017-12192)

A flaw was found in the Linux kernel's implementation of associative arrays introduced in 3.13. This functionality was backported to the 3.10 kernels in Red Hat Enterprise Linux 7. The flaw involved a null pointer dereference in assoc_array_apply_edit() due to incorrect node-splitting in assoc_array implementation. This affects the keyring key type and thus key addition and link creation operations may cause the kernel to panic.(CVE-2017-12193)

A divide-by-zero vulnerability was found in the __tcp_select_window function in the Linux kernel. This can result in a kernel panic causing a local denial of service.(CVE-2017-14106)

The move_pages system call in mm/migrate.c in the Linux kernel doesn't check the effective uid of the target process. This enables a local attacker to learn the memory layout of a setuid executable allowing mitigation of ASLR.(CVE-2017-14140)

The iscsi_if_rx() function in 'drivers/scsi/scsi_transport_iscsi.c' in the Linux kernel from v2.6.24-rc1 through 4.13.2 allows local users to cause a denial of service (a system panic) by making a number of certain syscalls by leveraging incorrect length validation in the kernel code.(CVE-2017-14489)

The sg_ioctl() function in 'drivers/scsi/sg.c' in the Linux kernel, from version 4.12-rc1 to 4.14-rc2, allows local users to obtain sensitive information from uninitialized kernel heap-memory locations via an SG_GET_REQUEST_TABLE ioctl call for '/dev/sg0'.(CVE-2017-14991)

The tower_probe function in drivers/usb/misc/legousbtower.c in the Linux kernel before 4.8.1 allows local users (who are physically proximate for inserting a crafted USB device) to gain privileges by leveraging a write-what-where condition that occurs after a race condition and a NULL pointer dereference.(CVE-2017-15102)

A vulnerability was found in the Linux kernel when peeling off an association to the socket in another network namespace. All transports in this association are not to be rehashed and keep ...

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