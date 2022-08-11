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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0076");
  script_cve_id("CVE-2013-6885", "CVE-2013-7421", "CVE-2014-3601", "CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-7970", "CVE-2014-8133", "CVE-2014-8134", "CVE-2014-8989", "CVE-2014-9322", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9428", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9644", "CVE-2015-1421", "CVE-2015-1465");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 18:23:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0076)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0076");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0076.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15223");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.24");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.25");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.26");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.27");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.28");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.29");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.30");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.31");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.32");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2015-0076 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on upstream -longterm 3.14.32 and fixes the
following security issues:

The microcode on AMD 16h 00h through 0Fh processors does not properly handle
the interaction between locked instructions and write-combined memory types,
which allows local users to cause a denial of service (system hang) via a
crafted application, aka the errata 793 issue (CVE-2013-6885)

The kvm_iommu_map_pages function in virt/kvm/iommu.c in the Linux kernel
through 3.16.1 miscalculates the number of pages during the handling of
a mapping failure, which allows guest OS users to (1) cause a denial of
service (host OS memory corruption) or possibly have unspecified other
impact by triggering a large gfn value or (2) cause a denial of service
(host OS memory consumption) by triggering a small gfn value that leads
to permanently pinned pages (CVE-2014-3601).

The WRMSR processing functionality in the KVM subsystem in the Linux
kernel through 3.17.2 does not properly handle the writing of a non-
canonical address to a model-specific register, which allows guest OS
users to cause a denial of service (host OS crash) by leveraging guest
OS privileges, related to the wrmsr_interception function in
arch/x86/kvm/svm.c and the handle_wrmsr function in arch/x86/kvm/vmx.c
(CVE-2014-3610).

Race condition in the __kvm_migrate_pit_timer function in
arch/x86/kvm/i8254.c in the KVM subsystem in the Linux kernel through
3.17.2 allows guest OS users to cause a denial of service (host OS crash)
by leveraging incorrect PIT emulation (CVE-2014-3611).

arch/x86/kvm/vmx.c in the KVM subsystem in the Linux kernel through 3.17.2
does not have an exit handler for the INVVPID instruction, which allows
guest OS users to cause a denial of service (guest OS crash) via a crafted
application (CVE-2014-3646).

arch/x86/kvm/emulate.c in the KVM subsystem in the Linux kernel through
3.17.2 does not properly perform RIP changes, which allows guest OS users
to cause a denial of service (guest OS crash) via a crafted application
(CVE-2014-3647).

The pivot_root implementation in fs/namespace.c in the Linux kernel through
3.17 does not properly interact with certain locations of a chroot directory,
which allows local users to cause a denial of service (mount-tree loop) via
. (dot) values in both arguments to the pivot_root system call
(CVE-2014-7970).

arch/x86/kernel/tls.c in the Thread Local Storage (TLS) implementation in
the Linux kernel through 3.18.1 allows local users to bypass the espfix
protection mechanism, and consequently makes it easier for local users to
bypass the ASLR protection mechanism, via a crafted application that makes
a set_thread_area system call and later reads a 16-bit value (CVE-2014-8133).

The paravirt_ops_setup function in arch/x86/kernel/kvm.c in the Linux kernel
through 3.18 uses an improper paravirt_enabled setting for KVM guest kernels,
which makes it easier for guest OS ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~3.14.32~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-3.14.32-1.mga4", rpm:"kernel-tmb-desktop-3.14.32-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-3.14.32-1.mga4", rpm:"kernel-tmb-desktop-devel-3.14.32-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~3.14.32~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~3.14.32~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-3.14.32-1.mga4", rpm:"kernel-tmb-desktop586-3.14.32-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-devel-3.14.32-1.mga4", rpm:"kernel-tmb-desktop586-devel-3.14.32-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-devel-latest", rpm:"kernel-tmb-desktop586-devel-latest~3.14.32~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-latest", rpm:"kernel-tmb-desktop586-latest~3.14.32~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-3.14.32-1.mga4", rpm:"kernel-tmb-laptop-3.14.32-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-devel-3.14.32-1.mga4", rpm:"kernel-tmb-laptop-devel-3.14.32-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-devel-latest", rpm:"kernel-tmb-laptop-devel-latest~3.14.32~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-latest", rpm:"kernel-tmb-laptop-latest~3.14.32~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-3.14.32-1.mga4", rpm:"kernel-tmb-server-3.14.32-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-devel-3.14.32-1.mga4", rpm:"kernel-tmb-server-devel-3.14.32-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-devel-latest", rpm:"kernel-tmb-server-devel-latest~3.14.32~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-latest", rpm:"kernel-tmb-server-latest~3.14.32~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-3.14.32-1.mga4", rpm:"kernel-tmb-source-3.14.32-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~3.14.32~1.mga4", rls:"MAGEIA4"))) {
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
