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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0215");
  script_cve_id("CVE-2021-23133", "CVE-2021-31440", "CVE-2021-31829", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-3491", "CVE-2021-3506");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0215)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0215");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0215.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28917");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.34");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.35");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.36");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.37");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus, kernel-linus' package(s) announced via the MGASA-2021-0215 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.10.37 and fixes at least the
following security issues:

It was discovered that the io_uring implementation of the Linux kernel did
not properly enforce the MAX_RW_COUNT limit in some situations. A local
attacker could use this to cause a denial of service (system crash) or
execute arbitrary code (CVE-2021-3491).

An out-of-bounds (OOB) memory access flaw was found in fs/f2fs/node.c in
the f2fs module in the Linux kernel in versions before 5.12.0-rc4. A bounds
check failure allows a local attacker to gain access to out-of-bounds
memory leading to a system crash or a leak of internal kernel information
(CVE-2021-3506).

A race condition in Linux kernel SCTP sockets (net/sctp/socket.c) before
5.12-rc8 can lead to kernel privilege escalation from the context of a
network service or an unprivileged process. If sctp_destroy_sock is called
without sock_net(sk)->sctp.addr_wq_lock then an element is removed from
the auto_asconf_splist list without any proper locking. This can be
exploited by an attacker with network service privileges to escalate to
root or from the context of an unprivileged user directly if a
BPF_CGROUP_INET_SOCK_CREATE is attached which denies creation of some
SCTP socket.
NOTE! This already had a fix in kernel-5.10.33, but that fix caused some
systems to deadlock, so this is now fixed in a better way (CVE-2021-23133).

bpf: Fix propagation of 32 bit unsigned bounds from 64 bit bounds
(CVE-2021-31440).

kernel/bpf/verifier.c in the Linux kernel through 5.12.1 performs undesirable
speculative loads, leading to disclosure of stack content via side-channel
attacks. The specific concern is not protecting the BPF stack area against
speculative loads. Also, the BPF stack can contain uninitialized data that
might represent sensitive information previously operated on by the kernel
(CVE-2021-31829).

net/bluetooth/hci_request.c in the Linux kernel through 5.12.2 has a race
condition for removal of the HCI controller (CVE-2021-32399).

In the Linux kernel before 5.12.4, net/bluetooth/hci_event.c has a
use-after-free when destroying an hci_chan. This leads to writing an
arbitrary value. (CVE-2021-33034).

For other upstream fixes, see the referenced changelogs.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.10.37-1.mga7", rpm:"kernel-linus-5.10.37-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.10.37~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.10.37-1.mga7", rpm:"kernel-linus-devel-5.10.37-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.10.37~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.10.37~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.10.37~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.10.37-1.mga7", rpm:"kernel-linus-source-5.10.37-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.10.37~1.mga7", rls:"MAGEIA7"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.10.37-1.mga8", rpm:"kernel-linus-5.10.37-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.10.37~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.10.37-1.mga8", rpm:"kernel-linus-devel-5.10.37-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.10.37~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.10.37~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.10.37~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.10.37-1.mga8", rpm:"kernel-linus-source-5.10.37-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.10.37~1.mga8", rls:"MAGEIA8"))) {
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
