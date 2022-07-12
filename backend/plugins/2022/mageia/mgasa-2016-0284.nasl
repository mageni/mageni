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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0284");
  script_cve_id("CVE-2016-1237", "CVE-2016-1583", "CVE-2016-4470", "CVE-2016-4794", "CVE-2016-4951", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5829");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 22:29:00 +0000 (Thu, 06 Dec 2018)");

  script_name("Mageia: Security Advisory (MGASA-2016-0284)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0284");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0284.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19057");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.14");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.15");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.16");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2016-0284 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update is based on the upstream 4.4.16 kernel and fixes at least these
security issues:

nfsd in the Linux kernel through 4.6.3 allows local users to bypass intended
file-permission restrictions by setting a POSIX ACL, related to nfs2acl.c,
nfs3acl.c, and nfs4acl.c. (CVE-2016-1237).

The ecryptfs_privileged_open function in fs/ecryptfs/kthread.c in the Linux
kernel before 4.6.3 allows local users to gain privileges or cause a denial
of service (stack memory consumption) via vectors involving crafted mmap
calls for /proc pathnames, leading to recursive pagefault handling
(CVE-2016-1583).

The key_reject_and_link function in security/keys/key.c in the Linux kernel
through 4.6.3 does not ensure that a certain data structure is initialized,
which allows local users to cause a denial of service (system crash) via
vectors involving a crafted keyctl request2 command (CVE-2016-4470).

Use-after-free vulnerability in mm/percpu.c in the Linux kernel through 4.6
allows local users to cause a denial of service (BUG) or possibly have
unspecified other impact via crafted use of the mmap and bpf system calls
(CVE-2016-4794).

The tipc_nl_publ_dump function in net/tipc/socket.c in the Linux kernel
through 4.6 does not verify socket existence, which allows local users to
cause a denial of service (NULL pointer dereference and system crash) or
possibly have unspecified other impact via a dumpit operation
(CVE-2016-4951).

The compat IPT_SO_SET_REPLACE setsockopt implementation in the netfilter
subsystem in the Linux kernel before 4.6.3 allows local users to gain
privileges or cause a denial of service (memory corruption) by leveraging
in-container root access to provide a crafted offset value that triggers
an unintended decrement. (CVE-2016-4997).

The IPT_SO_SET_REPLACE setsockopt implementation in the netfilter subsystem
in the Linux kernel before 4.6 allows local users to cause a denial of
service (out-of-bounds read) or possibly obtain sensitive information from
kernel heap memory by leveraging in-container root access to provide a
crafted offset value that leads to crossing a ruleset blob boundary
(CVE-2016-4998).

Multiple heap-based buffer overflows in the hiddev_ioctl_usage function in
drivers/hid/usbhid/hiddev.c in the Linux kernel through 4.6.3 allow local
users to cause a denial of service or possibly have unspecified other impact
via a crafted (1) HIDIOCGUSAGES or (2) HIDIOCSUSAGES ioctl call
(CVE-2016-5829).

For other fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-4.4.16-1.mga5", rpm:"kernel-linus-4.4.16-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~4.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-4.4.16-1.mga5", rpm:"kernel-linus-devel-4.4.16-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~4.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~4.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~4.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-4.4.16-1.mga5", rpm:"kernel-linus-source-4.4.16-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~4.4.16~1.mga5", rls:"MAGEIA5"))) {
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
