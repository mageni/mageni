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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0216");
  script_cve_id("CVE-2019-1543", "CVE-2019-2848", "CVE-2019-2850", "CVE-2019-2859", "CVE-2019-2863", "CVE-2019-2864", "CVE-2019-2865", "CVE-2019-2866", "CVE-2019-2867", "CVE-2019-2873", "CVE-2019-2874", "CVE-2019-2875", "CVE-2019-2876", "CVE-2019-2877");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-16 23:48:00 +0000 (Tue, 16 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2019-0216)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(6|7)");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0216");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0216.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25161");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html#AppendixOVIR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-vboxadditions, kmod-virtualbox, kmod-virtualbox, virtualbox, virtualbox' package(s) announced via the MGASA-2019-0216 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL versions 1.1.0 through 1.1.0j and 1.1.1 through 1.1.1b are
susceptible to a vulnerability that could lead to disclosure of sensitive
information or the addition or modification of data (CVE-2019-1543).

Oracle VM VirtualBox prior to 6.0.10 has an easily exploitable vulnerability
that allows low privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result in
unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of Oracle VM VirtualBox (CVE-2019-2848).

Oracle VM VirtualBox prior to 6.0.10 has an easily exploitable vulnerability
that allows low privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful
attacks require human interaction from a person other than the attacker.
Successful attacks of this vulnerability can result in unauthorized ability
to cause a partial denial of service (partial DOS) of Oracle VM VirtualBox
(CVE-2019-2850).

Oracle VM VirtualBox prior to 6.0.10 has an easily exploitable vulnerability
that allows low privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result in
takeover of Oracle VM VirtualBox (CVE-2019-2859).

Oracle VM VirtualBox prior to 6.0.10 has an easily exploitable vulnerability
that allows low privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result in
unauthorized access to critical data or complete access to all Oracle VM
VirtualBox accessible data (CVE-2019-2863).

Oracle VM VirtualBox prior to 6.0.10 has a difficult to exploit
vulnerability allows high privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle
VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks
may significantly impact additional products. Successful attacks of this
vulnerability can result in takeover of Oracle VM VirtualBox
(CVE-2019-2864, CVE-2019-2865).

Oracle VM VirtualBox prior to 6.0.10 has an easily exploitable vulnerability
allows high privileged attacker with logon to the infrastructure where
Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kmod-vboxadditions, kmod-virtualbox, kmod-virtualbox, virtualbox, virtualbox' package(s) on Mageia 6, Mageia 7.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.131-desktop-1.mga6", rpm:"vboxadditions-kernel-4.14.131-desktop-1.mga6~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.131-desktop586-1.mga6", rpm:"vboxadditions-kernel-4.14.131-desktop586-1.mga6~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.131-server-1.mga6", rpm:"vboxadditions-kernel-4.14.131-server-1.mga6~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.131-desktop-1.mga6", rpm:"virtualbox-kernel-4.14.131-desktop-1.mga6~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.131-desktop586-1.mga6", rpm:"virtualbox-kernel-4.14.131-desktop586-1.mga6~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.131-server-1.mga6", rpm:"virtualbox-kernel-4.14.131-server-1.mga6~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.1.18-desktop-1.mga7", rpm:"virtualbox-kernel-5.1.18-desktop-1.mga7~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.1.18-desktop586-1.mga7", rpm:"virtualbox-kernel-5.1.18-desktop586-1.mga7~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.1.18-server-1.mga7", rpm:"virtualbox-kernel-5.1.18-server-1.mga7~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~6.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.0.10~1.mga7", rls:"MAGEIA7"))) {
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
