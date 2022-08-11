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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0105");
  script_cve_id("CVE-2020-36221", "CVE-2020-36222", "CVE-2020-36223", "CVE-2020-36224", "CVE-2020-36225", "CVE-2020-36226", "CVE-2020-36227", "CVE-2020-36228", "CVE-2020-36229", "CVE-2020-36230", "CVE-2021-27212");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0105)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0105");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0105.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28300");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4724-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4744-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap, openldap' package(s) announced via the MGASA-2021-0105 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenLDAP incorrectly handled Certificate Exact
Assertion processing. A remote attacker could possibly use this issue to cause
OpenLDAP to crash, resulting in a denial of service (CVE-2020-36221).

It was discovered that OpenLDAP incorrectly handled saslAuthzTo processing. A
remote attacker could use this issue to cause OpenLDAP to crash, resulting in
a denial of service, or possibly execute arbitrary code (CVE-2020-36222,
CVE-2020-36224, CVE-2020-36225, CVE-2020-36226).

It was discovered that OpenLDAP incorrectly handled Return Filter control
handling. A remote attacker could use this issue to cause OpenLDAP to crash,
resulting in a denial of service, or possibly execute arbitrary code
(CVE-2020-36223).

It was discovered that OpenLDAP incorrectly handled certain cancel operations.
A remote attacker could possibly use this issue to cause OpenLDAP to crash,
resulting in a denial of service (CVE-2020-36227).

It was discovered that OpenLDAP incorrectly handled Certificate List Extract
Assertion processing. A remote attacker could possibly use this issue to cause
OpenLDAP to crash, resulting in a denial of service (CVE-2020-36228).

It was discovered that OpenLDAP incorrectly handled X.509 DN parsing. A remote
attacker could possibly use this issue to cause OpenLDAP to crash, resulting
in a denial of service (CVE-2020-36229, CVE-2020-36230).

Pasi Saarinen discovered that OpenLDAP incorrectly handled certain short
timestamps. A remote attacker could possibly use this issue to cause OpenLDAP
to crash, resulting in a denial of service (CVE-2021-27212).");

  script_tag(name:"affected", value:"'openldap, openldap' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2", rpm:"lib64ldap2.4_2~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2-devel", rpm:"lib64ldap2.4_2-devel~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2-static-devel", rpm:"lib64ldap2.4_2-static-devel~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2", rpm:"libldap2.4_2~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2-devel", rpm:"libldap2.4_2-devel~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2-static-devel", rpm:"libldap2.4_2-static-devel~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-back_bdb", rpm:"openldap-back_bdb~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-back_mdb", rpm:"openldap-back_mdb~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-back_sql", rpm:"openldap-back_sql~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-doc", rpm:"openldap-doc~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers-devel", rpm:"openldap-servers-devel~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-testprogs", rpm:"openldap-testprogs~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-tests", rpm:"openldap-tests~2.4.50~1.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2", rpm:"lib64ldap2.4_2~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2-devel", rpm:"lib64ldap2.4_2-devel~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2-static-devel", rpm:"lib64ldap2.4_2-static-devel~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2", rpm:"libldap2.4_2~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2-devel", rpm:"libldap2.4_2-devel~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2-static-devel", rpm:"libldap2.4_2-static-devel~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-back_bdb", rpm:"openldap-back_bdb~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-back_mdb", rpm:"openldap-back_mdb~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-back_sql", rpm:"openldap-back_sql~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-doc", rpm:"openldap-doc~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers-devel", rpm:"openldap-servers-devel~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-testprogs", rpm:"openldap-testprogs~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-tests", rpm:"openldap-tests~2.4.57~1.1.mga8", rls:"MAGEIA8"))) {
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
