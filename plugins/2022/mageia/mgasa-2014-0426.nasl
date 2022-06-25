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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0426");
  script_cve_id("CVE-2013-4148", "CVE-2013-4149", "CVE-2013-4150", "CVE-2013-4151", "CVE-2013-4526", "CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4530", "CVE-2013-4531", "CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2013-4540", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0142", "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145", "CVE-2014-0146", "CVE-2014-0147", "CVE-2014-0148", "CVE-2014-0150", "CVE-2014-0182", "CVE-2014-0222", "CVE-2014-0223", "CVE-2014-3461", "CVE-2014-3615", "CVE-2014-3640");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-13 00:25:00 +0000 (Thu, 13 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0426)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0426");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0426.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13096");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-May/133345.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-June/134053.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-September/137578.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-October/140130.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-0420.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-0704.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-0743.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-1669.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2182-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the MGASA-2014-0426 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated qemu packages fix security vulnerabilities:

Michael S. Tsirkin discovered that QEMU incorrectly handled vmxnet3 devices.
A local guest could possibly use this issue to cause a denial of service, or
possibly execute arbitrary code on the host (CVE-2013-4544).

Multiple integer overflow, input validation, logic error, and buffer
overflow flaws were discovered in various QEMU block drivers. An attacker
able to modify a disk image file loaded by a guest could use these flaws to
crash the guest, or corrupt QEMU process memory on the host, potentially
resulting in arbitrary code execution on the host with the privileges of
the QEMU process (CVE-2014-0143, CVE-2014-0144, CVE-2014-0145,
CVE-2014-0147).

A buffer overflow flaw was found in the way the virtio_net_handle_mac()
function of QEMU processed guest requests to update the table of MAC
addresses. A privileged guest user could use this flaw to corrupt QEMU
process memory on the host, potentially resulting in arbitrary code
execution on the host with the privileges of the QEMU process
(CVE-2014-0150).

A divide-by-zero flaw was found in the seek_to_sector() function of the
parallels block driver in QEMU. An attacker able to modify a disk image
file loaded by a guest could use this flaw to crash the guest
(CVE-2014-0142).

A NULL pointer dereference flaw was found in the QCOW2 block driver in
QEMU. An attacker able to modify a disk image file loaded by a guest could
use this flaw to crash the guest (CVE-2014-0146).

It was found that the block driver for Hyper-V VHDX images did not
correctly calculate BAT (Block Allocation Table) entries due to a missing
bounds check. An attacker able to modify a disk image file loaded by a
guest could use this flaw to crash the guest (CVE-2014-0148).

An out-of-bounds memory access flaw was found in the way QEMU's IDE device
driver handled the execution of SMART EXECUTE OFFLINE commands.
A privileged guest user could use this flaw to corrupt QEMU process memory
on the host, which could potentially result in arbitrary code execution on
the host with the privileges of the QEMU process (CVE-2014-2894).

Two integer overflow flaws were found in the QEMU block driver for QCOW
version 1 disk images. A user able to alter the QEMU disk image files
loaded by a guest could use either of these flaws to corrupt QEMU process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process
(CVE-2014-0222, CVE-2014-0223).

Multiple buffer overflow, input validation, and out-of-bounds write flaws
were found in the way the virtio, virtio-net, virtio-scsi, and usb drivers
of QEMU handled state loading after migration. A user able to alter the
savevm data (either on the disk or over the wire during migration) could
use either of these flaws to corrupt QEMU process memory on the
(destination) host, which could potentially result in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~1.6.2~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.6.2~1.2.mga4", rls:"MAGEIA4"))) {
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
