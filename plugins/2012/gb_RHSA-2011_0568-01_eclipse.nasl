###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for eclipse RHSA-2011:0568-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00019.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870642");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:38:49 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-4647");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("RedHat Update for eclipse RHSA-2011:0568-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eclipse'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"eclipse on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The Eclipse software development environment provides a set of tools for
  C/C++ and Java development.

  A cross-site scripting (XSS) flaw was found in the Eclipse Help Contents
  web application. An attacker could use this flaw to perform a cross-site
  scripting attack against victims by tricking them into visiting a
  specially-crafted Eclipse Help URL. (CVE-2010-4647)

  The following Eclipse packages have been upgraded to the versions found in
  the official upstream Eclipse Helios SR1 release, providing a number of
  bug fixes and enhancements over the previous versions:

  * eclipse to 3.6.1. (BZ#656329)

  * eclipse-cdt to 7.0.1. (BZ#656333)

  * eclipse-birt to 2.6.0. (BZ#656391)

  * eclipse-emf to 2.6.0. (BZ#656344)

  * eclipse-gef to 3.6.1. (BZ#656347)

  * eclipse-mylyn to 3.4.2. (BZ#656337)

  * eclipse-rse to 3.2. (BZ#656338)

  * eclipse-dtp to 1.8.1. (BZ#656397)

  * eclipse-changelog to 2.7.0. (BZ#669499)

  * eclipse-valgrind to 0.6.1. (BZ#669460)

  * eclipse-callgraph to 0.6.1. (BZ#669462)

  * eclipse-oprofile to 0.6.1. (BZ#670228)

  * eclipse-linuxprofilingframework to 0.6.1. (BZ#669461)

  In addition, the following updates were made to the dependencies of the
  Eclipse packages above:

  * icu4j to 4.2.1. (BZ#656342)

  * sat4j to 2.2.0. (BZ#661842)

  * objectweb-asm to 3.2. (BZ#664019)

  * jetty-eclipse to 6.1.24. (BZ#661845)

  This update includes numerous upstream bug fixes and enhancements, such as:

  * The Eclipse IDE and Java Development Tools (JDT):

  - - projects and folders can filter out resources in the workspace.

  - - new virtual folder and linked files support.

  - - the full set of UNIX file permissions is now supported.

  - - addition of the stop button to cancel long-running wizard tasks.

  - - Java editor now shows multiple quick-fixes via problem hover.

  - - new support for running JUnit version 4 tests.

  - - over 200 upstream bug fixes.

  * The Eclipse C/C++ Development Tooling (CDT):

  - - new Codan framework has been added for static code analysis.

  - - refactoring improvements such as stored refactoring history.

  - - compile and build errors now highlighted in the build console.

  - - switch to the new DSF debugger framework.

  - - new template view support.

  - - over 600 upstream bug fixes.

  This update also fixes the following bugs:

  * Incorrect URIs for GNU Tools in the 'Help Contents' window have been
  fixed. (BZ#622713)

  * The profiling of binaries did not work if an Eclipse project was not in
  an Eclipse workspace. This up ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"eclipse-birt", rpm:"eclipse-birt~2.6.0~1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-callgraph", rpm:"eclipse-callgraph~0.6.1~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-cdt", rpm:"eclipse-cdt~7.0.1~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-changelog", rpm:"eclipse-changelog~2.7.0~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-debuginfo", rpm:"eclipse-debuginfo~3.6.1~6.13.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-dtp", rpm:"eclipse-dtp~1.8.1~1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-emf", rpm:"eclipse-emf~2.6.0~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-gef", rpm:"eclipse-gef~3.6.1~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-jdt", rpm:"eclipse-jdt~3.6.1~6.13.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-linuxprofilingframework", rpm:"eclipse-linuxprofilingframework~0.6.1~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-mylyn", rpm:"eclipse-mylyn~3.4.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-mylyn-cdt", rpm:"eclipse-mylyn-cdt~3.4.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-mylyn-java", rpm:"eclipse-mylyn-java~3.4.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-mylyn-pde", rpm:"eclipse-mylyn-pde~3.4.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-mylyn-trac", rpm:"eclipse-mylyn-trac~3.4.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-mylyn-webtasks", rpm:"eclipse-mylyn-webtasks~3.4.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-mylyn-wikitext", rpm:"eclipse-mylyn-wikitext~3.4.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-oprofile", rpm:"eclipse-oprofile~0.6.1~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-oprofile-debuginfo", rpm:"eclipse-oprofile-debuginfo~0.6.1~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-pde", rpm:"eclipse-pde~3.6.1~6.13.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-platform", rpm:"eclipse-platform~3.6.1~6.13.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-rcp", rpm:"eclipse-rcp~3.6.1~6.13.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-rse", rpm:"eclipse-rse~3.2~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-swt", rpm:"eclipse-swt~3.6.1~6.13.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eclipse-valgrind", rpm:"eclipse-valgrind~0.6.1~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icu4j-eclipse", rpm:"icu4j-eclipse~4.2.1~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jetty-eclipse", rpm:"jetty-eclipse~6.1.24~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"objectweb-asm", rpm:"objectweb-asm~3.2~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sat4j", rpm:"sat4j~2.2.0~4.0.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
