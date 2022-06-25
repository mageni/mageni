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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0373");
  script_cve_id("CVE-2013-0343", "CVE-2013-1059", "CVE-2013-2140", "CVE-2013-2147", "CVE-2013-2851", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2891", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2894", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897", "CVE-2013-2898", "CVE-2013-2899", "CVE-2013-2929", "CVE-2013-2930", "CVE-2013-4162", "CVE-2013-4163", "CVE-2013-4254", "CVE-2013-4299", "CVE-2013-4348", "CVE-2013-4350", "CVE-2013-4387", "CVE-2013-4470", "CVE-2013-4513", "CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6376", "CVE-2013-6378", "CVE-2013-6380", "CVE-2013-6381", "CVE-2013-6382", "CVE-2013-6383");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-01-04 04:44:00 +0000 (Sat, 04 Jan 2014)");

  script_name("Mageia: Security Advisory (MGASA-2013-0373)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0373");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0373.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11465");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_3.9");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_3.10");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.1");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.2");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.3");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.4");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.5");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.6");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.7");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.8");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.9");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.10");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.11");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.12");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.13");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.14");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.15");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.16");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.17");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.18");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.19");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.20");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.21");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.22");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.23");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.24");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2013-0373 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update provides an update to the 3.10 longterm branch,
currently 3.10.24 and fixes the following security issues:

The ipv6_create_tempaddr function in net/ipv6/addrconf.c in the Linux
kernel through 3.10 does not properly handle problems with the generation
of IPv6 temporary addresses, which allows remote attackers to cause a
denial of service (excessive retries and address-generation outage), and
consequently obtain sensitive information, via ICMPv6 Router Advertisement
(RA) messages. (CVE-2013-0343)

net/ceph/auth_none.c in the Linux kernel through 3.10 allows remote
attackers to cause a denial of service (NULL pointer dereference and
system crash) or possibly have unspecified other impact via an auth_reply
message that triggers an attempted build_request operation.
(CVE-2013-1059)

The dispatch_discard_io function in drivers/block/xen-blkback/blkback.c in
the Xen blkback implementation in the Linux kernel before 3.10.5 allows
guest OS users to cause a denial of service (data loss) via filesystem
write operations on a read-only disk that supports the (1)
BLKIF_OP_DISCARD (aka discard or TRIM) or (2) SCSI UNMAP feature.
(CVE-2013-2140)

The HP Smart Array controller disk-array driver and Compaq SMART2
controller disk-array driver in the Linux kernel through 3.9.4 do not
initialize certain data structures, which allows local users to obtain
sensitive information from kernel memory via (1) a crafted IDAGETPCIINFO
command for a /dev/ida device, related to the ida_locked_ioctl function in
drivers/block/cpqarray.c or (2) a crafted CCISS_PASSTHRU32 command for a
/dev/cciss device, related to the cciss_ioctl32_passthru function in
drivers/block/cciss.c. (CVE-2013-2147)

Format string vulnerability in the register_disk function in block/genhd.c
in the Linux kernel through 3.9.4 allows local users to gain privileges by
leveraging root access and writing format string specifiers to
/sys/module/md_mod/parameters/new_array in order to create a crafted
/dev/md device name. (CVE-2013-2851)

Multiple array index errors in drivers/hid/hid-core.c in the Human
Interface Device (HID) subsystem in the Linux kernel through 3.11
allow physically proximate attackers to execute arbitrary code or
cause a denial of service (heap memory corruption) via a crafted
device that provides an invalid Report ID (CVE-2013-2888).

drivers/hid/hid-zpff.c in the Human Interface Device (HID) subsystem
in the Linux kernel through 3.11, when CONFIG_HID_ZEROPLUS is enabled,
allows physically proximate attackers to cause a denial of service
(heap-based out-of-bounds write) via a crafted device (CVE-2013-2889).

drivers/hid/hid-steelseries.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11, when CONFIG_HID_STEELSERIES is
enabled, allows physically proximate attackers to cause a denial of
service (heap-based out-of-bounds write) via a crafted ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-3.10.24-2.mga3", rpm:"kernel-tmb-desktop-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-3.10.24-2.mga3", rpm:"kernel-tmb-desktop-devel-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-3.10.24-2.mga3", rpm:"kernel-tmb-desktop586-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-devel-3.10.24-2.mga3", rpm:"kernel-tmb-desktop586-devel-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-devel-latest", rpm:"kernel-tmb-desktop586-devel-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-latest", rpm:"kernel-tmb-desktop586-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-3.10.24-2.mga3", rpm:"kernel-tmb-laptop-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-devel-3.10.24-2.mga3", rpm:"kernel-tmb-laptop-devel-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-devel-latest", rpm:"kernel-tmb-laptop-devel-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-latest", rpm:"kernel-tmb-laptop-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-3.10.24-2.mga3", rpm:"kernel-tmb-server-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-devel-3.10.24-2.mga3", rpm:"kernel-tmb-server-devel-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-devel-latest", rpm:"kernel-tmb-server-devel-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-latest", rpm:"kernel-tmb-server-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-3.10.24-2.mga3", rpm:"kernel-tmb-source-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
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
