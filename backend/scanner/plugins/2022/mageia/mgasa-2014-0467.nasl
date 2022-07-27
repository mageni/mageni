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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0467");
  script_cve_id("CVE-2014-3689", "CVE-2014-5263", "CVE-2014-7815");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 15:21:00 +0000 (Tue, 11 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0467)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0467");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0467.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14434");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2014-0426.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3066");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2409-1/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-November/143312.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, usbredir' package(s) announced via the MGASA-2014-0467 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Advanced Threat Research team at Intel Security reported that guest
provided parameter were insufficiently validated in rectangle functions in
the vmware-vga driver. A privileged guest user could use this flaw to write
into qemu address space on the host, potentially escalating their privileges
to those of the qemu host process (CVE-2014-3689).

It was discovered that QEMU incorrectly handled USB xHCI controller live
migration. An attacker could possibly use this issue to cause a denial of
service, or possibly execute arbitrary code (CVE-2014-5263).

James Spadaro of Cisco reported insufficiently sanitized bits_per_pixel from
the client in the QEMU VNC display driver. An attacker having access to the
guest's VNC console could use this flaw to crash the guest (CVE-2014-7815).

Additionally, the qemu update in MGASA-2014-0426 did not have USB redirection
support because Qemu 1.6.2 requires an updated libusbredirparser library.
This update has been built against the updated usbredirparser library.");

  script_tag(name:"affected", value:"'qemu, usbredir' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64usbredirhost-devel", rpm:"lib64usbredirhost-devel~0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64usbredirhost1", rpm:"lib64usbredirhost1~0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64usbredirparser-devel", rpm:"lib64usbredirparser-devel~0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64usbredirparser1", rpm:"lib64usbredirparser1~0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libusbredirhost-devel", rpm:"libusbredirhost-devel~0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libusbredirhost1", rpm:"libusbredirhost1~0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libusbredirparser-devel", rpm:"libusbredirparser-devel~0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libusbredirparser1", rpm:"libusbredirparser1~0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~1.6.2~1.5.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.6.2~1.5.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"usbredir", rpm:"usbredir~0.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"usbredir-devel", rpm:"usbredir-devel~0.6~1.mga4", rls:"MAGEIA4"))) {
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
