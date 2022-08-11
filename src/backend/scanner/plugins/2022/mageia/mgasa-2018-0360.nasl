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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0360");
  script_cve_id("CVE-2018-3005", "CVE-2018-3055", "CVE-2018-3085", "CVE-2018-3086", "CVE-2018-3087", "CVE-2018-3088", "CVE-2018-3089", "CVE-2018-3090", "CVE-2018-3091");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0360)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0360");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0360.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23421");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixOVIR");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-08/msg00077.html");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog#18");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2018-0360 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the virtualbox 5.1.18 maintenance release that
fixes at least the following security issues:

Fixed an easily exploitable vulnerability that allowed unauthenticated
attacker with logon to the infrastructure where Oracle VM VirtualBox
executes to compromise Oracle VM VirtualBox. Successful attacks of this
vulnerability can result in unauthorized ability to cause a partial denial
of service (partial DOS) of Oracle VM VirtualBox (CVE-2018-3005).

Fixed an easily exploitable vulnerability that allowed unauthenticated
attacker with logon to the infrastructure where Oracle VM VirtualBox
executes to compromise Oracle VM VirtualBox. Successful attacks require
human interaction from a person other than the attacker and while the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result
in unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of Oracle VM VirtualBox and unauthorized read access to a
subset of Oracle VM VirtualBox accessible data (CVE-2018-3055).

Fixed an easily exploitable vulnerability that allowed unauthenticated
attacker with logon to the infrastructure where Oracle VM VirtualBox
executes to compromise Oracle VM VirtualBox. Successful attacks require
human interaction from a person other than the attacker and while the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result
in unauthorized creation, deletion or modification access to critical data
or all Oracle VM VirtualBox accessible data as well as unauthorized read
access to a subset of Oracle VM VirtualBox accessible data and unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS) of
Oracle VM VirtualBox (CVE-2018-3085).

Fixed an easily exploitable vulnerability that allowed unauthenticated
attacker with logon to the infrastructure where Oracle VM VirtualBox
executes to compromise Oracle VM VirtualBox. Successful attacks require
human interaction from a person other than the attacker and while the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result
in takeover of Oracle VM VirtualBox (CVE-2018-3086, CVE-2018-3087,
CVE-2018-3088, CVE-2018-3089, CVE-2018-3090).

Fixed an easily exploitable vulnerability allows unauthenticated attacker
with logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. Successful attacks require human
interaction from a person other than the attacker and while the
vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
additional products. Successful attacks of this vulnerability can result
in unauthorized access to critical data or complete access to all Oracle
VM ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.65-desktop-1.mga6", rpm:"vboxadditions-kernel-4.14.65-desktop-1.mga6~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.65-desktop586-1.mga6", rpm:"vboxadditions-kernel-4.14.65-desktop586-1.mga6~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.65-server-1.mga6", rpm:"vboxadditions-kernel-4.14.65-server-1.mga6~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.65-desktop-1.mga6", rpm:"virtualbox-kernel-4.14.65-desktop-1.mga6~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.65-desktop586-1.mga6", rpm:"virtualbox-kernel-4.14.65-desktop586-1.mga6~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.65-server-1.mga6", rpm:"virtualbox-kernel-4.14.65-server-1.mga6~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~5.2.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-vboxvideo", rpm:"x11-driver-video-vboxvideo~5.2.18~1.mga6", rls:"MAGEIA6"))) {
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
