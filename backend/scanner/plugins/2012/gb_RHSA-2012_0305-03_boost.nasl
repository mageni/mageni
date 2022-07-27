###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for boost RHSA-2012:0305-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00054.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870563");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:57:09 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2008-0171", "CVE-2008-0172");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for boost RHSA-2012:0305-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'boost'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"boost on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The boost packages provide free, peer-reviewed, portable C++ source
  libraries with emphasis on libraries which work well with the C++ Standard
  Library.

  Invalid pointer dereference flaws were found in the way the Boost regular
  expression library processed certain, invalid expressions. An attacker able
  to make an application using the Boost library process a specially-crafted
  regular expression could cause that application to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2008-0171)

  NULL pointer dereference flaws were found in the way the Boost regular
  expression library processed certain, invalid expressions. An attacker able
  to make an application using the Boost library process a specially-crafted
  regular expression could cause that application to crash. (CVE-2008-0172)

  Red Hat would like to thank Will Drewry for reporting these issues.

  This update also fixes the following bugs:

  * Prior to this update, the construction of a regular expression object
  could fail when several regular expression objects were created
  simultaneously, such as in a multi-threaded program. With this update, the
  object variables have been moved from the shared memory to the stack. Now,
  the constructing function is thread safe. (BZ#472384)

  * Prior to this update, header files in several Boost libraries contained
  preprocessor directives that the GNU Compiler Collection (GCC) 4.4 could
  not handle. This update instead uses equivalent constructs that are
  standard C. (BZ#567722)

  All users of boost are advised to upgrade to these updated packages, which
  fix these issues.");
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

  if ((res = isrpmvuln(pkg:"boost", rpm:"boost~1.33.1~15.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-debuginfo", rpm:"boost-debuginfo~1.33.1~15.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-devel", rpm:"boost-devel~1.33.1~15.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-doc", rpm:"boost-doc~1.33.1~15.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
