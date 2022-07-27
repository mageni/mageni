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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0035");
  script_cve_id("CVE-2018-12179", "CVE-2018-12182", "CVE-2018-12183", "CVE-2019-0160", "CVE-2019-0161", "CVE-2019-14553", "CVE-2019-14558", "CVE-2019-14559", "CVE-2019-14562", "CVE-2019-14563", "CVE-2019-14575", "CVE-2019-14584", "CVE-2019-14586", "CVE-2019-14587");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2021-0035)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0035");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0035.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25939");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TQYVZRFEXSN3KS43AVH4D7QX553EZQYP/");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2020:1712");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4349-1/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/A23OH3MXQU7WURSP4PC66EXMG6INYFH6/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4684-1");
  script_xref(name:"URL", value:"https://github.com/tianocore/edk2/releases");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2' package(s) announced via the MGASA-2021-0035 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper configuration in system firmware for EDK II may allow unauthenticated
user to potentially enable escalation of privilege, information disclosure
and/or denial of service via local access. (CVE-2018-12179).

Insufficient memory write check in SMM service for EDK II may allow an
authenticated user to potentially enable escalation of privilege, information
disclosure and/or denial of service via local access. (CVE-2018-12182).

Stack overflow in DxeCore for EDK II may allow an unauthenticated user to
potentially enable escalation of privilege, information disclosure and/or
denial of service via local access. (CVE-2018-12183).

Buffer overflow in system firmware for EDK II may allow unauthenticated user
to potentially enable escalation of privilege and/or denial of service via
network access. (CVE-2019-0160).

Stack overflow in XHCI for EDK II may allow an unauthenticated user to
potentially enable denial of service via local access. (CVE-2019-0161).

Improper authentication in EDK II may allow a privileged user to potentially
enable information disclosure via network access. (CVE-2019-14553).

Insufficient control flow management in BIOS firmware for 8th, 9th, 10th
Generation Intel(R) Core(TM), Intel(R) Celeron(R) Processor 4000 & 5000 Series
Processors may allow an authenticated user to potentially enable denial of
service via adjacent access. (CVE-2019-14558).

Uncontrolled resource consumption in EDK II may allow an unauthenticated user
to potentially enable denial of service via network access. (CVE-2019-14559).

Integer truncation in EDK II may allow an authenticated user to potentially
enable escalation of privilege via local access. (CVE-2019-14563).

Logic issue in DxeImageVerificationHandler() for EDK II may allow an
authenticated user to potentially enable escalation of privilege via local
access. (CVE-2019-14575).

EDK II incorrectly parsed signed PKCS #7 data. An attacker could use this
issue to cause EDK II to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2019-14584).

Use after free vulnerability in EDK II may allow an authenticated user to
potentially enable escalation of privilege, information disclosure and/or
denial of service via adjacent access. (CVE-2019-14586).

Logic issue EDK II may allow an unauthenticated user to potentially enable
denial of service via adjacent access. (CVE-2019-14587).

Integer overflow in DxeImageVerificationHandler() EDK II may allow an
authenticated user to potentially enable denial of service via local access.
(CVE-2019-14562).");

  script_tag(name:"affected", value:"'edk2' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"edk2", rpm:"edk2~20201127stable~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-aarch64", rpm:"edk2-aarch64~20201127stable~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-arm", rpm:"edk2-arm~20201127stable~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-ovmf", rpm:"edk2-ovmf~20201127stable~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-ovmf-ia32", rpm:"edk2-ovmf-ia32~20201127stable~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-qosb", rpm:"edk2-qosb~20201127stable~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-tools", rpm:"edk2-tools~20201127stable~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-tools-doc", rpm:"edk2-tools-doc~20201127stable~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-tools-python", rpm:"edk2-tools-python~20201127stable~1.mga7", rls:"MAGEIA7"))) {
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
