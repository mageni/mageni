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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0047");
  script_cve_id("CVE-2016-1238", "CVE-2017-12837", "CVE-2017-12883", "CVE-2017-6512");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0047)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0047");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0047.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19051");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3628");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3873");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3982");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl, perl-File-Path, perl-MIME-Charset, perl-MIME-EncWords, perl-Module-Build, perl-Module-Load-Conditional, perl-Net-DNS, perl-Sys-Syslog, perl-Unicode-LineBreak, perl-libintl-perl' package(s) announced via the MGASA-2018-0047 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"John Lightsey and Todd Rinaldo reported that the opportunistic loading of
optional modules can make many programs unintentionally load code from the
current working directory (which might be changed to another directory
without the user realising) and potentially leading to privilege escalation
(CVE-2016-1238).

The cPanel Security Team reported a time of check to time of use (TOCTTOU)
race condition flaw in File::Path, a core module from Perl to create or
remove directory trees. An attacker can take advantage of this flaw to set
the mode on an attacker-chosen file to a attacker-chosen value
(CVE-2017-6512).

Jakub Wilk reported a heap buffer overflow flaw in the regular expression
compiler, allowing a remote attacker to cause a denial of service via a
 specially crafted regular expression with the case-insensitive modifier
(CVE-2017-12837).

Jakub Wilk reported a buffer over-read flaw in the regular expression
parser, allowing a remote attacker to cause a denial of service or
information leak (CVE-2017-12883).

The perl-libintl-perl, perl-MIME-Charset, perl-MIME-EncWords,
perl-Module-Build, perl-Sys-Syslog, and perl-Unicode-LineBreak packages
have been patched and the perl-Module-Load-Conditional and perl-Net-DNS
packages have been updated to fix CVE-2016-1238 as well.

The perl-File-Path package has also been patched to fix CVE-2017-6512.");

  script_tag(name:"affected", value:"'perl, perl-File-Path, perl-MIME-Charset, perl-MIME-EncWords, perl-Module-Build, perl-Module-Load-Conditional, perl-Net-DNS, perl-Sys-Syslog, perl-Unicode-LineBreak, perl-libintl-perl' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.20.1~8.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-Path", rpm:"perl-File-Path~2.90.0~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-MIME-Charset", rpm:"perl-MIME-Charset~1.11.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-MIME-EncWords", rpm:"perl-MIME-EncWords~1.14.2~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Build", rpm:"perl-Module-Build~0.421.0~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Load-Conditional", rpm:"perl-Module-Load-Conditional~0.680.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Net-DNS", rpm:"perl-Net-DNS~1.90.0~0.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Sys-Syslog", rpm:"perl-Sys-Syslog~0.330.0~7.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Unicode-LineBreak", rpm:"perl-Unicode-LineBreak~2014.60.0~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.20.1~8.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.20.1~8.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.20.1~8.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libintl-perl", rpm:"perl-libintl-perl~1.230.0~6.1.mga5", rls:"MAGEIA5"))) {
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
