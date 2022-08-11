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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0155");
  script_cve_id("CVE-2014-0054", "CVE-2014-1904");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-20 01:29:00 +0000 (Fri, 20 Apr 2018)");

  script_name("Mageia: Security Advisory (MGASA-2014-0155)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0155");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0155.html");
  script_xref(name:"URL", value:"http://www.gopivotal.com/security/cve-2014-0054");
  script_xref(name:"URL", value:"http://www.gopivotal.com/security/cve-2014-1904");
  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2890");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13126");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'springframework, springframework' package(s) announced via the MGASA-2014-0155 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated springframework packages fix security vulnerabilities:

Jaxb2RootElementHttpMessageConverter in Spring MVC processes external XML
entities (CVE-2014-0054).

Spring MVC introduces a cross-site scripting vulnerability if the action on a
Spring form is not specified (CVE-2014-1904).");

  script_tag(name:"affected", value:"'springframework, springframework' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"springframework", rpm:"springframework~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-aop", rpm:"springframework-aop~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-beans", rpm:"springframework-beans~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-context", rpm:"springframework-context~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-context-support", rpm:"springframework-context-support~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-expression", rpm:"springframework-expression~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-instrument", rpm:"springframework-instrument~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-javadoc", rpm:"springframework-javadoc~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-jdbc", rpm:"springframework-jdbc~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-jms", rpm:"springframework-jms~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-orm", rpm:"springframework-orm~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-oxm", rpm:"springframework-oxm~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-struts", rpm:"springframework-struts~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-tx", rpm:"springframework-tx~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-web", rpm:"springframework-web~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-webmvc", rpm:"springframework-webmvc~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-webmvc-portlet", rpm:"springframework-webmvc-portlet~3.1.1~21.3.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"springframework", rpm:"springframework~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-aop", rpm:"springframework-aop~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-beans", rpm:"springframework-beans~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-context", rpm:"springframework-context~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-context-support", rpm:"springframework-context-support~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-expression", rpm:"springframework-expression~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-instrument", rpm:"springframework-instrument~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-instrument-tomcat", rpm:"springframework-instrument-tomcat~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-javadoc", rpm:"springframework-javadoc~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-jdbc", rpm:"springframework-jdbc~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-jms", rpm:"springframework-jms~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-orm", rpm:"springframework-orm~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-oxm", rpm:"springframework-oxm~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-struts", rpm:"springframework-struts~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-test", rpm:"springframework-test~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-tx", rpm:"springframework-tx~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-web", rpm:"springframework-web~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-webmvc", rpm:"springframework-webmvc~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-webmvc-portlet", rpm:"springframework-webmvc-portlet~3.1.4~2.2.mga4", rls:"MAGEIA4"))) {
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
