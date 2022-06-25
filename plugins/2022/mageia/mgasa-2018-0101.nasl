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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0101");
  script_cve_id("CVE-2017-3736", "CVE-2017-5715", "CVE-2018-2676", "CVE-2018-2685", "CVE-2018-2686", "CVE-2018-2687", "CVE-2018-2688", "CVE-2018-2689", "CVE-2018-2690", "CVE-2018-2693", "CVE-2018-2694", "CVE-2018-2698");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0101)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0101");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0101.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22408");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html#AppendixOVIR");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2018-0101 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Oracle VM VirtualBox incorporate the OpenSSL software libraries to provide
cryptographic capabilities. OpenSSL versions through 1.0.2m and 1.1.0g are
susceptible to a vulnerability that could allow an attacker to recover
encryption keys and access protected communications (CVE-2017-3736).

Systems with microprocessors utilizing speculative execution and indirect
branch prediction may allow unauthorized disclosure of information to an
attacker with local user access via a side-channel analysis (CVE-2017-5715).

Oracle VM VirtualBox prior to 5.2.6 has easily exploitable vulnerabilities
that allows high privileged attacker with logon to the infrastructure where
VirtualBox executes to compromise it. While the vulnerability is in
VirtualBox, attacks may significantly impact additional products. Successful
attacks of this vulnerability can result in takeover of VirtualBox
(CVE-2018-2676).

Oracle VM VirtualBox prior to 5.2.6 has easily exploitable vulnerabilities
that allows unauthenticated attacker with logon to the infrastructure where
VirtualBox executes to compromise it. Successful attacks require human
interaction from a person other than the attacker and while the
vulnerability is in VirtualBox, attacks may significantly impact additional
products. Successful attacks of this vulnerability can result in takeover
of VirtualBox (CVE-2018-2685, CVE-2018-2686, CVE-2018-2687, CVE-2018-2688,
CVE-2018-2689, CVE-2018-2690).

Oracle VM VirtualBox Guest Additions prior to 5.2.6 has an easily exploitable
vulnerability allows low privileged attacker with logon to the infrastructure
where VirtualBox executes to compromise it. Successful attacks require human
interaction from a person other than the attacker and while the vulnerability
is in VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in takeover of VirtualBox
(CVE-2018-2693).

Oracle VM VirtualBox prior to 5.2.6 has easily exploitable vulnerabilities
that allows low privileged attacker with logon to the infrastructure where
VirtualBox executes to compromise it. While the vulnerability is in
VirtualBox, attacks may significantly impact additional products. Successful
attacks of this vulnerability can result in takeover of VirtualBox
(CVE-2018-2694, CVE-2018-2698).

For other fixes in this update, see the referenced changelog.");

  script_tag(name:"affected", value:"'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.13-desktop-1.mga6", rpm:"vboxadditions-kernel-4.14.13-desktop-1.mga6~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.13-desktop586-1.mga6", rpm:"vboxadditions-kernel-4.14.13-desktop586-1.mga6~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.13-server-1.mga6", rpm:"vboxadditions-kernel-4.14.13-server-1.mga6~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.13-desktop-1.mga6", rpm:"virtualbox-kernel-4.14.13-desktop-1.mga6~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.13-desktop586-1.mga6", rpm:"virtualbox-kernel-4.14.13-desktop586-1.mga6~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.13-server-1.mga6", rpm:"virtualbox-kernel-4.14.13-server-1.mga6~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~5.2.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-vboxvideo", rpm:"x11-driver-video-vboxvideo~5.2.6~1.mga6", rls:"MAGEIA6"))) {
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
