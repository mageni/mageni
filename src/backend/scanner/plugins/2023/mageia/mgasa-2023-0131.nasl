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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0131");
  script_cve_id("CVE-2023-1393");
  script_tag(name:"creation_date", value:"2023-04-12 04:12:44 +0000 (Wed, 12 Apr 2023)");
  script_version("2023-04-12T11:20:00+0000");
  script_tag(name:"last_modification", value:"2023-04-12 11:20:00 +0000 (Wed, 12 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 14:42:00 +0000 (Fri, 07 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0131)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0131");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0131.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31732");
  script_xref(name:"URL", value:"https://lists.x.org/archives/xorg-announce/2023-March/003374.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5380");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5986-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/CB62PUAZRE2ZK6PDX6OZ2WSYXDJGBGTS/");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2023:1592");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SW2NRC3V53PIBXFPFBVWCOM2MDDILWQS/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tigervnc, x11-server' package(s) announced via the MGASA-2023-0131 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in X.Org Server Overlay Window. A Use-After-Free may lead
to local privilege escalation. If a client explicitly destroys the
compositor overlay window (aka COW), the Xserver would leave a dangling
pointer to that window in the CompScreen structure, which will trigger a
use-after-free later. (CVE-2023-1393)");

  script_tag(name:"affected", value:"'tigervnc, x11-server' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.11.0~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-java", rpm:"tigervnc-java~1.11.0~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server", rpm:"tigervnc-server~1.11.0~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-module", rpm:"tigervnc-server-module~1.11.0~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server", rpm:"x11-server~1.20.14~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-common", rpm:"x11-server-common~1.20.14~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-devel", rpm:"x11-server-devel~1.20.14~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-source", rpm:"x11-server-source~1.20.14~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xdmx", rpm:"x11-server-xdmx~1.20.14~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xephyr", rpm:"x11-server-xephyr~1.20.14~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xnest", rpm:"x11-server-xnest~1.20.14~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xorg", rpm:"x11-server-xorg~1.20.14~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xvfb", rpm:"x11-server-xvfb~1.20.14~4.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xwayland", rpm:"x11-server-xwayland~1.20.14~4.3.mga8", rls:"MAGEIA8"))) {
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
