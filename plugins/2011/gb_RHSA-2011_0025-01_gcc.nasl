###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gcc RHSA-2011:0025-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-January/msg00007.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870375");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-01-14 16:07:43 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2010-0831", "CVE-2010-2322");
  script_name("RedHat Update for gcc RHSA-2011:0025-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"gcc on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The gcc packages include C, C++, Java, Fortran, Objective C, and Ada 95 GNU
  compilers, along with related support libraries. The libgcj package
  provides fastjar, an archive tool for Java Archive (JAR) files.

  Two directory traversal flaws were found in the way fastjar extracted JAR
  archive files. If a local, unsuspecting user extracted a specially-crafted
  JAR file, it could cause fastjar to overwrite arbitrary files writable by
  the user running fastjar. (CVE-2010-0831, CVE-2010-2322)

  This update also fixes the following bugs:

  * The option -print-multi-os-directory in the gcc --help output is not in
  the gcc(1) man page. This update applies an upstream patch to amend this.
  (BZ#529659)

  * An internal assertion in the compiler tried to check that a C++ static
  data member is external which resulted in errors. This was because when the
  compiler optimizes C++ anonymous namespaces the declarations were no longer
  marked external as everything on anonymous namespaces is local to the
  current translation. This update corrects the assertion to resolve this
  issue. (BZ#503565, BZ#508735, BZ#582682)

  * Attempting to compile certain .cpp files could have resulted in an
  internal compiler error. This update resolves this issue. (BZ#527510)

  * PrintServiceLookup.lookupPrintServices with an appropriate DocFlavor
  failed to return a list of printers under gcj. This update includes a
  backported patch to correct this bug in the printer lookup service.
  (BZ#578382)

  * GCC would not build against xulrunner-devel-1.9.2. This update removes
  gcjwebplugin from the GCC RPM. (BZ#596097)

  * When a SystemTap generated kernel module was compiled, gcc reported an
  internal compiler error and gets a segmentation fault. This update applies
  a patch that, instead of crashing, assumes it can point to anything.
  (BZ#605803)

  * There was a performance issue with libstdc++ regarding all objects
  derived from or using std::streambuf because of lock contention between
  threads. This patch ensures reload uses the same value from _S_global for
  the comparison, _M_add_reference () and _M_impl member of the class.
  (BZ#635708)

  All gcc users should upgrade to these updated packages, which contain
  backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"cpp", rpm:"cpp~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc", rpm:"gcc~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-c++", rpm:"gcc-c++~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-debuginfo", rpm:"gcc-debuginfo~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-gfortran", rpm:"gcc-gfortran~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-gnat", rpm:"gcc-gnat~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-java", rpm:"gcc-java~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-objc++", rpm:"gcc-objc++~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-objc", rpm:"gcc-objc~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcc", rpm:"libgcc~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj", rpm:"libgcj~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj-devel", rpm:"libgcj-devel~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj-src", rpm:"libgcj-src~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgfortran", rpm:"libgfortran~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnat", rpm:"libgnat~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmudflap", rpm:"libmudflap~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmudflap-devel", rpm:"libmudflap-devel~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libobjc", rpm:"libobjc~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libstdc++", rpm:"libstdc++~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libstdc++-devel", rpm:"libstdc++-devel~4.1.2~50.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
