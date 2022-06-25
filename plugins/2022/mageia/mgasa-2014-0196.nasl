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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0196");
  script_cve_id("CVE-2014-0472", "CVE-2014-0473", "CVE-2014-0474");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-07 02:59:00 +0000 (Sat, 07 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2014-0196)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0196");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0196.html");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2014/apr/21/security/");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2169-1/");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2169-2/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13251");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django, python-django, python-django14' package(s) announced via the MGASA-2014-0196 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-django and python-dgango14 packages fix security vulnerabilities:

Benjamin Bach discovered that Django incorrectly handled dotted Python
paths when using the reverse() function. An attacker could use this issue
to cause Django to import arbitrary modules from the Python path, resulting
in possible code execution. (CVE-2014-0472)

Paul McMillan discovered that Django incorrectly cached certain pages that
contained CSRF cookies. An attacker could possibly use this flaw to obtain
a valid cookie and perform attacks which bypass the CSRF restrictions.
(CVE-2014-0473)

Michael Koziarski discovered that Django did not always perform explicit
conversion of certain fields when using a MySQL database. An attacker
could possibly use this issue to obtain unexpected results. (CVE-2014-0474)");

  script_tag(name:"affected", value:"'python-django, python-django, python-django14' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.4.11~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.5.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django-doc", rpm:"python-django-doc~1.5.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django14", rpm:"python-django14~1.4.11~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~1.5.6~1.1.mga4", rls:"MAGEIA4"))) {
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
