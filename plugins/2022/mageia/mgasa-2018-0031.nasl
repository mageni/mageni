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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0031");
  script_cve_id("CVE-2016-1246", "CVE-2016-1249", "CVE-2016-1251", "CVE-2017-10788", "CVE-2017-10789");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 18:24:00 +0000 (Wed, 12 Jul 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0031)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0031");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0031.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19522");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3684");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/NY3AHSF4ZPQQ5OGYZYNQOD7TBL7CAG4F/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/7BLHU5FAHMKZBZ4LAHIASWUJVK4O6JS6/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/3CWISRFDOB7YRPBNDD3BNIQHSRYBDD6S/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TAWTNCSYWNBJHJR4AYQAAW65JVWDWMEW/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-DBD-mysql, perl-DBD-mysql' package(s) announced via the MGASA-2018-0031 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pali Rohar discovered that DBD::mysql constructed an error message in a
fixed-length buffer, leading to a crash (_FORTIFY_SOURCE failure) and,
potentially, to denial of service (CVE-2016-1246).

A vulnerability was discovered in perl-DBD-MySQL that can lead to an
out-of-bounds read when using server side prepared statements with an
unaligned number of placeholders in WHERE condition and output fields in
SELECT expression (CVE-2016-1249).

There is a vulnerability of type use-after-free affecting DBD::mysql
before 4.041 when used with mysql_server_prepare=1 (CVE-2016-1251).

The DBD::mysql module through 4.043 for Perl allows remote attackers to
cause a denial of service (use-after-free and application crash) or
possibly have unspecified other impact by triggering (1) certain error
responses from a MySQL server or (2) a loss of a network connection to a
MySQL server. The use-after-free defect was introduced by relying on
incorrect Oracle mysql_stmt_close documentation and code examples
(CVE-2017-10788).

The DBD::mysql module through 4.043 for Perl uses the mysql_ssl=1 setting
to mean that SSL is optional (even though this setting's documentation has
a 'your communication with the server will be encrypted' statement), which
allows man-in-the-middle attackers to spoof servers via a
cleartext-downgrade attack (CVE-2017-10789).

Note that the CVE-2016-1246, CVE-2017-1249, and CVE-2016-1251 issues only
affected Mageia 5.

Also note that server-side prepared statements are disabled by default.");

  script_tag(name:"affected", value:"'perl-DBD-mysql, perl-DBD-mysql' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"perl-DBD-mysql", rpm:"perl-DBD-mysql~4.43.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"perl-DBD-mysql", rpm:"perl-DBD-mysql~4.43.0~1.mga6", rls:"MAGEIA6"))) {
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
