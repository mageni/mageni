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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1523");
  script_version("2020-01-23T12:03:55+0000");
  script_cve_id("CVE-2013-2899", "CVE-2014-3601", "CVE-2014-6410", "CVE-2015-0572", "CVE-2015-8709", "CVE-2015-8953", "CVE-2016-10150", "CVE-2016-3841", "CVE-2016-4805", "CVE-2016-9120", "CVE-2017-10663", "CVE-2017-11473", "CVE-2017-12168", "CVE-2017-12193", "CVE-2017-14489", "CVE-2017-16644", "CVE-2017-16648", "CVE-2017-7533", "CVE-2017-9985", "CVE-2018-10879");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 12:03:55 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:03:55 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1523)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1523");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1523 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The snd_msndmidi_input_read function in sound/isa/msnd/msnd_midi.c in the Linux kernel through 4.11.7 allows local users to cause a denial of service (over-boundary access) or possibly have unspecified other impact by changing the value of a message queue head pointer between two kernel reads of that value, aka a 'double fetch' vulnerability.(CVE-2017-9985

An assertion failure issue was found in the Linux kernel's KVM hypervisor module built to support visualization on ARM64 architecture platforms. The failure could occur while accessing Performance Monitors Cycle Count Register (PMCCNTR) from a guest. A privileged guest user could use this flaw to crash the host kernel resulting in denial of service.(CVE-2017-12168

The iscsi_if_rx() function in 'drivers/scsi/scsi_transport_iscsi.c' in the Linux kernel from v2.6.24-rc1 through 4.13.2 allows local users to cause a denial of service (a system panic) by making a number of certain syscalls by leveraging incorrect length validation in the kernel code.(CVE-2017-14489

The hdpvr_probe function in drivers/media/usb/hdpvr/hdpvr-core.c in the Linux kernel through 4.13.11 allows local users to cause a denial of service (improper error handling and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16644

The dvb frontend management subsystem in the Linux kernel contains a use-after-free which can allow a malicious user to write to memory that may be assigned to another kernel structure. This could create memory corruption, panic, or possibly other side affects.(CVE-2017-16648

It was found that the Linux kernel's IPv6 implementation mishandled socket options. A local attacker could abuse concurrent access to the socket options to escalate their privileges, or cause a denial of service (use-after-free and system crash) via a crafted sendmsg system call.(CVE-2016-3841

A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause a use-after-free in ext4_xattr_set_entry function and a denial of service or unspecified other impact may occur by renaming a file in a crafted ext4 filesystem image.(CVE-2018-10879

A race condition was found in the Linux kernel, present since v3.14-rc1 through v4.12. The race happens between threads of inotify_handle_event() and vfs_rename() while running the rename operation against the same file. As a result of the race the next slab data or the slab's free list pointer can be corrupted with attacker-controlled data, which may lead to the privilege escalation.(CVE-2017-7533

A privilege-escalation vulnerability was discovered in the Linux k ...

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