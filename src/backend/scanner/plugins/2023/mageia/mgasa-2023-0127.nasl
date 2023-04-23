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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0127");
  script_cve_id("CVE-2023-0225");
  script_tag(name:"creation_date", value:"2023-04-07 04:12:44 +0000 (Fri, 07 Apr 2023)");
  script_version("2023-04-10T10:08:59+0000");
  script_tag(name:"last_modification", value:"2023-04-10 10:08:59 +0000 (Mon, 10 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-09 02:50:00 +0000 (Sun, 09 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0127)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0127");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0127.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31735");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-0225.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-0922.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-0614.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-March/014245.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ldb, samba' package(s) announced via the MGASA-2023-0127 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Deletion of AD DC 'dnsHostname' attribute by unprivileged authenticated
users (CVE-2023-0225)
Read access controlled AD LDAP attributes (CVE-2023-0614)
Cleartext password sending by AD DC admin tool (CVE-2023-0922)");

  script_tag(name:"affected", value:"'ldb, samba' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"ctdb", rpm:"ctdb~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldb", rpm:"ldb~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldb-utils", rpm:"ldb-utils~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldb-devel", rpm:"lib64ldb-devel~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldb2", rpm:"lib64ldb2~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pyldb-util-devel", rpm:"lib64pyldb-util-devel~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pyldb-util2", rpm:"lib64pyldb-util2~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-dc0", rpm:"lib64samba-dc0~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-devel", rpm:"lib64samba-devel~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-test0", rpm:"lib64samba-test0~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba1", rpm:"lib64samba1~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient-devel", rpm:"lib64smbclient-devel~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb-devel", rpm:"libldb-devel~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb2", rpm:"libldb2~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpyldb-util-devel", rpm:"libpyldb-util-devel~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpyldb-util2", rpm:"libpyldb-util2~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-dc0", rpm:"libsamba-dc0~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-devel", rpm:"libsamba-devel~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-test0", rpm:"libsamba-test0~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba1", rpm:"libsamba1~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ldb", rpm:"python3-ldb~2.5.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-samba", rpm:"python3-samba~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dc", rpm:"samba-dc~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-krb5-printing", rpm:"samba-krb5-printing~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test", rpm:"samba-test~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~4.16.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-modules", rpm:"samba-winbind-modules~4.16.10~1.mga8", rls:"MAGEIA8"))) {
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
