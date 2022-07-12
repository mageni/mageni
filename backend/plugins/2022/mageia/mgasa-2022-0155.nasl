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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0155");
  script_cve_id("CVE-2022-0168", "CVE-2022-1158", "CVE-2022-1198", "CVE-2022-1204", "CVE-2022-1205", "CVE-2022-1263", "CVE-2022-1353", "CVE-2022-28388", "CVE-2022-28389", "CVE-2022-28390", "CVE-2022-29582");
  script_tag(name:"creation_date", value:"2022-05-03 08:04:45 +0000 (Tue, 03 May 2022)");
  script_version("2022-05-03T20:09:21+0000");
  script_tag(name:"last_modification", value:"2022-05-04 10:05:48 +0000 (Wed, 04 May 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-09 15:28:00 +0000 (Sat, 09 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0155)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0155");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0155.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30331");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.33");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.34");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.35");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2022-0155 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.35 and fixes at least the
following security issues:

A denial of service (DOS) issue was found in the Linux kernel
smb2_ioctl_query_info function in the fs/cifs/smb2ops.c Common Internet
File System (CIFS) due to an incorrect return from the memdup_user function.
This flaw allows a local, privileged (CAP_SYS_ADMIN) attacker to crash the
system (CVE-2022-0168).

x86/kvm: cmpxchg_gpte can write to pfns outside the userspace region
(CVE-2022-1158).

Use-after-free vulnerabilities in drivers/net/hamradio/6pack.c allow
attacker to crash linux kernel by simulating Amateur Radio from user-space
(CVE-2022-1198).

Use-after-free flaw was found in the Linux kernel's Amateur Radio AX.25
protocol functionality in the way a user connects with the protocol. This
flaw allows a local user to crash the system (CVE-2022-1204).

A NULL pointer dereference flaw was found in the Linux kernel's Amateur
Radio AX.25 protocol functionality in the way a user connects with the
protocol. This flaw allows a local user to crash the system
(CVE-2022-1205).

A null pointer dereference was found in the kvm module which can lead to
denial of service (CVE-2022-1263).

A vulnerability was found in the pfkey_register function in net/key/af_key.c
in the Linux kernel. This flaw allows a local, unprivileged user to gain
access to kernel memory, leading to a system crash or a leak of internal
kernel information (CVE-2022-1353).

usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel
through 5.17.1 has a double free (CVE-2022-28388).

mcba_usb_start_xmit in drivers/net/can/usb/mcba_usb.c in the Linux kernel
through 5.17.1 has a double free (CVE-2022-28389).

ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel
through 5.17.1 has a double free (CVE-2022-28390).

In the Linux kernel before 5.17.3, fs/io_uring.c has a use-after-free due
to a race condition in io_uring timeouts. This can be triggered by a local
user who has no access to any user namespace (CVE-2022-29582).

For other upstream fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.35-1.mga8", rpm:"kernel-linus-5.15.35-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.35~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.35-1.mga8", rpm:"kernel-linus-devel-5.15.35-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.35~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.35~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.35~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.35-1.mga8", rpm:"kernel-linus-source-5.15.35-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.35~1.mga8", rls:"MAGEIA8"))) {
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
