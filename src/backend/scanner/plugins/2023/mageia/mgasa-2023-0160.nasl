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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0160");
  script_cve_id("CVE-2023-21987", "CVE-2023-21988", "CVE-2023-21989", "CVE-2023-21990", "CVE-2023-21991", "CVE-2023-21999", "CVE-2023-22000", "CVE-2023-22001", "CVE-2023-22002");
  script_tag(name:"creation_date", value:"2023-05-08 04:13:35 +0000 (Mon, 08 May 2023)");
  script_version("2023-05-08T09:08:51+0000");
  script_tag(name:"last_modification", value:"2023-05-08 09:08:51 +0000 (Mon, 08 May 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-18 20:37:00 +0000 (Tue, 18 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0160)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0160");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0160.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31813");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog-7.0#v8");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixOVIR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2023-0160 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the upstream 7.0.8 maintenance release that
fixes at least the following security vulnerabilities:

Vulnerability in the Oracle VM VirtualBox prior to 7.0.8. A difficult to
exploit vulnerability allows low privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
significantly impact additional products (scope change). Successful attacks
of this vulnerability can result in takeover of Oracle VM VirtualBox.
(CVE-2023-21987, CVE-2023-21988).

Vulnerability in the Oracle VM VirtualBox prior to 7.0.8. An easily
exploitable vulnerability allows high privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
significantly impact additional products (scope change). Successful attacks
of this vulnerability can result in unauthorized access to critical data or
complete access to all Oracle VM VirtualBox accessible data.
(CVE-2023-21989).

Vulnerability in the Oracle VM VirtualBox prior to 7.0.8. An easily
exploitable vulnerability allows high privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
significantly impact additional products (scope change). Successful attacks
of this vulnerability can result in takeover of Oracle VM VirtualBox.
(CVE-2023-21990).

Vulnerability in the Oracle VM VirtualBox prior to 7.0.8. An easily
exploitable vulnerability allows high privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks
may significantly impact additional products (scope change). Successful
attacks of this vulnerability can result in unauthorized read access to a
subset of Oracle VM VirtualBox accessible data (CVE-2023-21991).

Vulnerability in the Oracle VM VirtualBox prior to 7.0.8. A difficult to
exploit vulnerability allows low privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle
VM VirtualBox. Successful attacks of this vulnerability can result in
unauthorized update, insert or delete access to some of Oracle VM
VirtualBox accessible data as well as unauthorized read access to a
subset of Oracle VM VirtualBox accessible data (CVE-2023-21999).

Vulnerability in the Oracle VM VirtualBox prior to 7.0.8. An easily
exploitable vulnerability allows high privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
significantly impact additional products (scope ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kmod-virtualbox, virtualbox' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~7.0.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~7.0.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~7.0.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~7.0.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~7.0.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~7.0.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.106-desktop-2.mga8", rpm:"virtualbox-kernel-5.15.106-desktop-2.mga8~7.0.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.106-server-2.mga8", rpm:"virtualbox-kernel-5.15.106-server-2.mga8~7.0.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~7.0.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~7.0.8~1.mga8", rls:"MAGEIA8"))) {
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
