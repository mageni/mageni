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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0406");
  script_cve_id("CVE-2018-11805", "CVE-2019-12420");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-13 19:15:00 +0000 (Mon, 13 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0406)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0406");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0406.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25860");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/12/12/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/12/12/2");
  script_xref(name:"URL", value:"https://svn.apache.org/repos/asf/spamassassin/branches/3.4/build/announcements/3.4.3.txt");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4584");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spamassassin, spamassassin-rules' package(s) announced via the MGASA-2019-0406 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

In Apache SpamAssassin before 3.4.3, nefarious CF files can be configured
to run system commands without any output or errors. With this, exploits
can be injected in a number of scenarios. In addition to upgrading to SA
3.4.3, we recommend that users should only use update channels or 3rdparty
.cf files from trusted places. (CVE-2018-11805)

In Apache SpamAssassin before 3.4.3, a message can be crafted in a way to
use excessive resources. Upgrading to SA 3.4.3 as soon as possible is the
recommended fix but details will not be shared publicly. (CVE-2019-12420)");

  script_tag(name:"affected", value:"'spamassassin, spamassassin-rules' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin", rpm:"perl-Mail-SpamAssassin~3.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin-Spamd", rpm:"perl-Mail-SpamAssassin-Spamd~3.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-rules", rpm:"spamassassin-rules~3.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-sa-compile", rpm:"spamassassin-sa-compile~3.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-spamc", rpm:"spamassassin-spamc~3.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-spamd", rpm:"spamassassin-spamd~3.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-tools", rpm:"spamassassin-tools~3.4.3~1.mga7", rls:"MAGEIA7"))) {
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
