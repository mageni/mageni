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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0208");
  script_cve_id("CVE-2014-0049", "CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0077", "CVE-2014-2851");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-26 13:50:00 +0000 (Wed, 26 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0208)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0208");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0208.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12994");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13080");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13255");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.18");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.17");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.16");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.15");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.14");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13267");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-rt' package(s) announced via the MGASA-2014-0208 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated kernel-rt provides upstream 3.12.18 kernel and fixes the following
security issues:

Buffer overflow in the complete_emulated_mmio function in arch/x86/kvm/
x86.c in the Linux kernel before 3.13.6 allows guest OS users to execute
arbitrary code on the host OS by leveraging a loop that triggers an
invalid memory copy affecting certain cancel_work_item data.
(CVE-2014-0049)

The get_rx_bufs function in drivers/vhost/net.c in the vhost-net subsystem
in the Linux kernel package before 2.6.32-431.11.2 on Red Hat Enterprise
Linux (RHEL) 6 does not properly handle vhost_get_vq_desc errors, which
allows guest OS users to cause a denial of service (host OS crash) via
unspecified vectors. (CVE-2014-0055)

The cifs_iovec_write function in fs/cifs/file.c in the Linux kernel through
3.13.5 does not properly handle uncached write operations that copy fewer
than the requested number of bytes, which allows local users to obtain
sensitive information from kernel memory, cause a denial of service
(memory corruption and system crash), or possibly gain privileges via a
writev system call with a crafted pointer. (CVE-2014-0069)

drivers/vhost/net.c in the Linux kernel before 3.13.10, when mergeable
buffers are disabled, does not properly validate packet lengths, which
allows guest OS users to cause a denial of service (memory corruption and
host OS crash) or possibly gain privileges on the host OS via crafted
packets, related to the handle_rx and get_rx_bufs functions.
(CVE-2014-0077)

Integer overflow in the ping_init_sock function in net/ipv4/ping.c in the
Linux kernel through 3.14.1 allows local users to cause a denial of service
(use-after-free and system crash) or possibly gain privileges via a crafted
application that leverages an improperly managed reference counter.
(CVE-2014-2851)

Other, otter fixes in this update:
- switch hugepages back to madvise to fix performance regression (mga#12994)
- enable Intel P-state driver (mga#13080)
- fix r8169 suspend/resume issue (mga#13255)
- RT patch has been updated to -rt25

For upstream merged fixes, read the referenced changelogs:");

  script_tag(name:"affected", value:"'kernel-rt' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-3.12.18-0.rt25.1.mga4", rpm:"kernel-rt-3.12.18-0.rt25.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~3.12.18~0.rt25.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-3.12.18-0.rt25.1.mga4", rpm:"kernel-rt-devel-3.12.18-0.rt25.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-latest", rpm:"kernel-rt-devel-latest~3.12.18~0.rt25.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-doc", rpm:"kernel-rt-doc~3.12.18~0.rt25.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-latest", rpm:"kernel-rt-latest~3.12.18~0.rt25.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-source-3.12.18-0.rt25.1.mga4", rpm:"kernel-rt-source-3.12.18-0.rt25.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-source-latest", rpm:"kernel-rt-source-latest~3.12.18~0.rt25.1.mga4", rls:"MAGEIA4"))) {
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
