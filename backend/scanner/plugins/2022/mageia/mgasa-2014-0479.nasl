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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0479");
  script_cve_id("CVE-2014-3601", "CVE-2014-3631", "CVE-2014-7970", "CVE-2014-7975");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 18:14:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0479)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0479");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0479.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14309");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.52");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.53");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.54");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.55");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.56");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.57");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.58");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-vserver' package(s) announced via the MGASA-2014-0479 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-vserver update is based on upstream -longterm 3.10.58 and
fixes the following security issues:

The kvm_iommu_map_pages function in virt/kvm/iommu.c in the Linux
kernel through 3.16.1 miscalculates the number of pages during the
handling of a mapping failure, which allows guest OS users to (1)
cause a denial of service (host OS memory corruption) or possibly
have unspecified other impact by triggering a large gfn value or
(2) cause a denial of service (host OS memory consumption) by
triggering a small gfn value that leads to permanently pinned
pages (CVE-2014-3601).

The assoc_array_gc function in the associative-array implementation
in lib/assoc_array.c in the Linux kernel before 3.16.3 does not
properly implement garbage collection, which allows local users to
cause a denial of service (NULL pointer dereference and system
crash) or possibly have unspecified other impact via multiple
'keyctl newring' operations followed by a 'keyctl timeout'
operation (CVE-2014-3631).

The pivot_root implementation in fs/namespace.c in the Linux kernel
through 3.17 does not properly interact with certain locations of
a chroot directory, which allows local users to cause a denial of
service (mount-tree loop) via . (dot) values in both arguments to
the pivot_root system call (CVE-2014-7970).

The do_umount function in fs/namespace.c in the Linux kernel
through 3.17 does not require the CAP_SYS_ADMIN capability for
do_remount_sb calls that change the root filesystem to read-only,
which allows local users to cause a denial of service (loss of
writability) by making certain unshare system calls, clearing the
/ MNT_LOCKED flag, and making an MNT_FORCE umount system call
(CVE-2014-7975).

For other fixes included in this update, read the referenced
changelogs.");

  script_tag(name:"affected", value:"'kernel-vserver' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-3.10.58-0.vs2.3.6.8.1.mga3", rpm:"kernel-vserver-3.10.58-0.vs2.3.6.8.1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver", rpm:"kernel-vserver~3.10.58~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-devel-3.10.58-0.vs2.3.6.8.1.mga3", rpm:"kernel-vserver-devel-3.10.58-0.vs2.3.6.8.1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-devel-latest", rpm:"kernel-vserver-devel-latest~3.10.58~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-doc", rpm:"kernel-vserver-doc~3.10.58~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-latest", rpm:"kernel-vserver-latest~3.10.58~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-source-3.10.58-0.vs2.3.6.8.1.mga3", rpm:"kernel-vserver-source-3.10.58-0.vs2.3.6.8.1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-source-latest", rpm:"kernel-vserver-source-latest~3.10.58~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
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
