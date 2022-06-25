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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0172");
  script_cve_id("CVE-2014-8159", "CVE-2015-1593", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-3331", "CVE-2015-3332");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2015-0172)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0172");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0172.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15613");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.33");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.34");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.35");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.36");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.37");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.38");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.39");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2015-0172 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream -longterm 3.14.39 and fixes
the following security issues:

It was found that the Linux kernel's Infiniband subsystem did not properly
sanitize input parameters while registering memory regions from user space
via the (u)verbs API. A local user with access to a /dev/infiniband/uverbsX
device could use this flaw to crash the system or, potentially, escalate
their privileges on the system (CVE-2014-8159)

The stack randomization feature in the Linux kernel before 3.19.1 on 64-bit
platforms uses incorrect data types for the results of bitwise left-shift
operations, which makes it easier for attackers to bypass the ASLR
protection mechanism by predicting the address of the top of the stack,
related to the randomize_stack_top function in fs/binfmt_elf.c and the
stack_maxrandom_size function in arch/x86/mm/mmap.c (CVE-2015-1593)

Xen 3.3.x through 4.5.x and the Linux kernel through 3.19.1 do not properly
restrict access to PCI command registers, which might allow local guest
users to cause a denial of service (non-maskable interrupt and host crash)
by disabling the (1) memory or (2) I/O decoding for a PCI Express device
and then accessing the device, which triggers an Unsupported Request
(UR) response (CVE-2015-2150)

Sasha Levin discovered that the LLC subsystem exposed some variables as
sysctls with the wrong type. On a 64-bit kernel, this possibly allows
privilege escalation from a process with CAP_NET_ADMIN capability, it
also results in a trivial information leak (CVE-2015-2041).

Sasha Levin discovered that the RDS subsystem exposed some variables as
sysctls with the wrong type. On a 64-bit kernel, this results in a
trivial information leak (CVE-2015-2042).

Andrew Lutomirski discovered that when a 64-bit task on an amd64 kernel
makes a fork(2) or clone(2) system call using int $0x80, the 32-bit
compatibility flag is set (correctly) but is not cleared on return.
As a result, both seccomp and audit will misinterpret the following
system call by the task(s), possibly leading to a violation of security
policy (CVE-2015-2830).

Stephan Mueller discovered that the optimised implementation of RFC4106
GCM for x86 processors that support AESNI miscalculated buffer addresses
in some cases. If an IPsec tunnel is configured to use this mode (also
known as AES-GCM-ESP) this can lead to memory corruption and crashes
(even without malicious traffic). This could potentially also result
in remote code execution (CVE-2015-3331).

Ben Hutchings discovered that the TCP Fast Open feature regressed in
Linux 3.16.7-ckt9, resulting in a kernel BUG when it is used.
This can be used as a local denial of service (CVE-2015-3332)

For other fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-3.14.39-1.mga4", rpm:"kernel-linus-3.14.39-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~3.14.39~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-3.14.39-1.mga4", rpm:"kernel-linus-devel-3.14.39-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~3.14.39~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~3.14.39~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~3.14.39~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-3.14.39-1.mga4", rpm:"kernel-linus-source-3.14.39-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~3.14.39~1.mga4", rls:"MAGEIA4"))) {
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
