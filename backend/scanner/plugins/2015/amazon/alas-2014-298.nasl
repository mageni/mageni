# Copyright (C) 2015 Eero Volotinen
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
  script_oid("1.3.6.1.4.1.25623.1.0.120161");
  script_version("2021-12-03T14:10:10+0000");
  script_tag(name:"creation_date", value:"2015-09-08 13:18:51 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"2021-12-07 11:00:26 +0000 (Tue, 07 Dec 2021)");
  script_name("Amazon Linux: Security Advisory (ALAS-2014-298)");
  script_tag(name:"insight", value:"This update fixes several vulnerabilities in the MySQL database server. (CVE-2014-0386, CVE-2014-0393, CVE-2014-0401, CVE-2014-0402, CVE-2014-0412, CVE-2014-0437, CVE-2013-5908 )A buffer overflow flaw was found in the way the MySQL command line client tool (mysql) processed excessively long version strings. If a user connected to a malicious MySQL server via the mysql client, the server could use this flaw to crash the mysql client or, potentially, execute arbitrary code as the user running the mysql client. (CVE-2014-0001 )");
  script_tag(name:"solution", value:"Run yum update mysql51 to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-298.html");
  script_cve_id("CVE-2014-0412", "CVE-2014-0437", "CVE-2013-5908", "CVE-2014-0393", "CVE-2014-0386", "CVE-2014-0001", "CVE-2014-0401", "CVE-2014-0402");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"The remote host is missing an update announced via the referenced Security Advisory.");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {
  if(!isnull(res = isrpmvuln(pkg:"mysql51-embedded", rpm:"mysql51-embedded~5.1.73~3.68.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql51-common", rpm:"mysql51-common~5.1.73~3.68.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql51", rpm:"mysql51~5.1.73~3.68.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql51-devel", rpm:"mysql51-devel~5.1.73~3.68.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql51-server", rpm:"mysql51-server~5.1.73~3.68.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql51-bench", rpm:"mysql51-bench~5.1.73~3.68.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql51-debuginfo", rpm:"mysql51-debuginfo~5.1.73~3.68.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql51-test", rpm:"mysql51-test~5.1.73~3.68.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql51-embedded-devel", rpm:"mysql51-embedded-devel~5.1.73~3.68.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql51-libs", rpm:"mysql51-libs~5.1.73~3.68.amzn1", rls:"AMAZON"))) {
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
