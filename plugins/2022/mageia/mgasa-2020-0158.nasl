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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0158");
  script_cve_id("CVE-2019-19768", "CVE-2019-19769", "CVE-2020-2732", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-8835", "CVE-2020-9383", "CVE-2020-9391");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 15:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0158)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0158");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0158.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26426");
  script_xref(name:"URL", value:"https://kernelnewbies.org/Linux_5.5");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.1");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.2");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.3");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.4");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.5");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.6");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.7");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.8");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.9");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.10");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.11");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.12");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.13");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.14");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.5.15");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2020-0158 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update is based on upstream 5.5.15 and fixes at least the following
security vulnerabilities:

In the Linux kernel 5.4.0-rc2, there is a use-after-free (read) in the
__blk_add_trace function in kernel/trace/blktrace.c (which is used to
fill out a blk_io_trace structure and place it in a per-cpu sub-buffer)
(CVE-2019-19768).

In the Linux kernel 5.3.10, there is a use-after-free (read) in the
perf_trace_lock_acquire function (related to include/trace/events/lock.h)
(CVE-2019-19769).

A flaw was found in the way KVM hypervisor handled instruction emulation
for the L2 guest when nested(=1) virtualization is enabled. In the
instruction emulation, the L2 guest could trick the L0 hypervisor into
accessing sensitive bits of the L1 hypervisor. An L2 guest could use this
flaw to potentially access information of the L1 hypervisor
(CVE-2020-2732).

There is a use-after-free vulnerability in the Linux kernel through 5.5.2
in the vc_do_resize function in drivers/tty/vt/vt.c (CVE-2020-8647).

There is a use-after-free vulnerability in the Linux kernel through 5.5.2
in the n_tty_receive_buf_common function in drivers/tty/n_tty.c
(CVE-2020-8648).

Manfred Paul discovered that the bpf verifier in the Linux kernel did not
properly calculate register bounds for certain operations. A local attacker
could use this to expose sensitive information (kernel memory) or gain
administrative privileges (CVE-2020-8835).

There is a use-after-free vulnerability in the Linux kernel through 5.5.2
in the vgacon_invert_region function in drivers/video/console/vgacon.c.
(CVE-2020-8649).

An issue was discovered in the Linux kernel through 5.5.6. set_fdc in
drivers/block/floppy.c leads to a wait_til_ready out-of-bounds read
because the FDC index is not checked for errors before assigning it,
aka CID-2e90ca68b0d2 (CVE-2020-9383).

An issue was discovered in the Linux kernel 5.4 and 5.5 through 5.5.6
on the AArch64 architecture. It ignores the top byte in the address
passed to the brk system call, potentially moving the memory break
downwards when the application expects it to move upwards, aka CID-
dcde237319e6. This has been observed to cause heap corruption with
the GNU C Library malloc implementation (CVE-2020-9391).

Security fixes and hardenings to the mac00211 layer to prevent leaking keys
and frames.

For other upstream fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.5.15-1.mga7", rpm:"kernel-linus-5.5.15-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.5.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.5.15-1.mga7", rpm:"kernel-linus-devel-5.5.15-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.5.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.5.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.5.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.5.15-1.mga7", rpm:"kernel-linus-source-5.5.15-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.5.15~1.mga7", rls:"MAGEIA7"))) {
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
