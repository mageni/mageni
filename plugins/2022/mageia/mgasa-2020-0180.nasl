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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0180");
  script_cve_id("CVE-2020-2741", "CVE-2020-2748", "CVE-2020-2758", "CVE-2020-2894", "CVE-2020-2902", "CVE-2020-2905", "CVE-2020-2907", "CVE-2020-2908", "CVE-2020-2909", "CVE-2020-2910", "CVE-2020-2911", "CVE-2020-2913", "CVE-2020-2914", "CVE-2020-2929", "CVE-2020-2951", "CVE-2020-2958", "CVE-2020-2959");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 14:49:00 +0000 (Thu, 25 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0180)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0180");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0180.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26506");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog-6.0#v20");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixOVIR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2020-0180 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the upstream 6.0.20 adding support for kernel 5.6
series and fixes the following security vulnerabilities:

Oracle VM VirtualBox before 6.0.20 has an easily exploitable vulnerability
that allows high privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result in
unauthorized access to critical data or complete access to all Oracle VM
VirtualBox accessible data (CVE-2020-2741).

Oracle VM VirtualBox before 6.0.20 has an easily exploitable vulnerability
that allows high privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result in
unauthorized read access to a subset of Oracle VM VirtualBox accessible
data (CVE-2020-2748).

Oracle VM VirtualBox before 6.0.20 has an easily exploitable vulnerability
that allows high privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result in
takeover of Oracle VM VirtualBox (CVE-2020-2758, CVE-2020-2894,
CVE-2020-2905, CVE-2020-2908).

Oracle VM VirtualBox before 6.0.20 has an easily exploitable vulnerability
that allows low privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result in
takeover of Oracle VM VirtualBox (CVE-2020-2902).

Oracle VM VirtualBox before 6.0.20 has an difficult to exploit vulnerability
that allows high privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result in
takeover of Oracle VM VirtualBox (CVE-2020-2907, CVE-2020-2911,
CVE-2020-2958).

Oracle VM VirtualBox before 6.0.20 has an easily exploitable vulnerability
that allows low privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox.
Successful attacks require human interaction from a person other than the
attacker. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial DOS)
of Oracle VM VirtualBox ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kmod-virtualbox, virtualbox' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.5.15-desktop-3.mga7", rpm:"virtualbox-kernel-5.5.15-desktop-3.mga7~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.5.15-desktop586-3.mga7", rpm:"virtualbox-kernel-5.5.15-desktop586-3.mga7~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.5.15-server-3.mga7", rpm:"virtualbox-kernel-5.5.15-server-3.mga7~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~6.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.0.20~1.mga7", rls:"MAGEIA7"))) {
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
