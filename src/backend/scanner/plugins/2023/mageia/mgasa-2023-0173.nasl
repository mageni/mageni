# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0173");
  script_cve_id("CVE-2023-1380", "CVE-2023-1859", "CVE-2023-2002", "CVE-2023-2248", "CVE-2023-31436");
  script_tag(name:"creation_date", value:"2023-05-22 04:13:07 +0000 (Mon, 22 May 2023)");
  script_version("2023-05-22T12:17:59+0000");
  script_tag(name:"last_modification", value:"2023-05-22 12:17:59 +0000 (Mon, 22 May 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-05 17:24:00 +0000 (Fri, 05 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0173)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0173");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0173.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31876");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.107");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.108");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.109");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.110");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2023-0173 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.110 and fixes at least
the following security issues:

A slab-out-of-bound read problem was found in brcmf_get_assoc_ies in
drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c.
This issue could occur when assoc_info->req_len data is bigger than the
size of the buffer, defined as WL_EXTRA_BUF_MAX, leading to a denial of
service (CVE-2023-1380).

It was discovered that a race condition existed in the Xen transport layer
implementation for the 9P file system protocol in the Linux kernel, leading
to a use-after-free vulnerability. A local attacker could use this to cause
a denial of service or expose sensitive information (CVE-2023-1859).

An insufficient permission check has been found in the Bluetooth subsystem
of the Linux kernel when handling ioctl system calls of HCI sockets.
This causes tasks without the proper CAP_NET_ADMIN capability can easily
mark HCI sockets as _trusted_. Trusted sockets are intended to enable the
sending and receiving of management commands and events, such as pairing
or connecting with a new device. As a result, unprivileged users can
acquire a trusted socket, leading to unauthorized execution of management
commands (CVE-2023-2002).

A heap out-of-bounds read/write vulnerability in the Linux Kernel traffic
control (QoS) subsystem can be exploited to achieve local privilege
escalation. The qfq_change_class function does not properly limit the lmax
variable which can lead to out-of-bounds read/write. If the TCA_QFQ_LMAX
value is not offered through nlattr, lmax is determined by the MTU value
of the network device. The MTU of the loopback device can be set up to
2^31-1 and as a result, it is possible to have an lmax value that exceeds
QFQ_MIN_LMAX (CVE-2023-2248).

qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13
allows an out-of-bounds write because lmax can exceed QFQ_MIN_LMAX
(CVE-2023-31436).

For other upstream fixes in this update, see the referenced changelogs.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.110-1.mga8", rpm:"kernel-linus-5.15.110-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.110~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.110-1.mga8", rpm:"kernel-linus-devel-5.15.110-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.110~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.110~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.110~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.110-1.mga8", rpm:"kernel-linus-source-5.15.110-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.110~1.mga8", rls:"MAGEIA8"))) {
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
