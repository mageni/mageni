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
  script_oid("1.3.6.1.4.1.25623.1.0.120466");
  script_version("2021-12-03T14:10:10+0000");
  script_tag(name:"creation_date", value:"2015-09-08 13:27:03 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"2021-12-06 11:03:13 +0000 (Mon, 06 Dec 2021)");
  script_name("Amazon Linux: Security Advisory (ALAS-2013-269)");
  script_tag(name:"insight", value:"The is_this_legal function in mod_dontdothat for Apache Subversion 1.4.0 through 1.7.13 and 1.8.0 through 1.8.4 allows remote attackers to bypass intended access restrictions and possibly cause a denial of service (resource consumption) via a relative URL in a REPORT request.The get_parent_resource function in repos.c in mod_dav_svn Apache HTTPD server module in Subversion 1.7.11 through 1.7.13 and 1.8.1 through 1.8.4, when built with assertions enabled and SVNAutoversioning is enabled, allows remote attackers to cause a denial of service (assertion failure and Apache process abort) via a non-canonical URL in a request, as demonstrated using a trailing /.");
  script_tag(name:"solution", value:"Run yum update subversion to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-269.html");
  script_cve_id("CVE-2013-4505", "CVE-2013-4558");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
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
  if(!isnull(res = isrpmvuln(pkg:"subversion-ruby", rpm:"subversion-ruby~1.7.14~1.36.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.7.14~1.36.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-javahl", rpm:"subversion-javahl~1.7.14~1.36.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.7.14~1.36.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-libs", rpm:"subversion-libs~1.7.14~1.36.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.7.14~1.36.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_dav_svn", rpm:"mod_dav_svn~1.7.14~1.36.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.7.14~1.36.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-python", rpm:"subversion-python~1.7.14~1.36.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-debuginfo", rpm:"subversion-debuginfo~1.7.14~1.36.amzn1", rls:"AMAZON"))) {
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
