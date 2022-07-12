###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for glibc CESA-2014:1110 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882019");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-10 06:20:44 +0200 (Wed, 10 Sep 2014)");
  script_cve_id("CVE-2014-0475", "CVE-2014-5119");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for glibc CESA-2014:1110 centos7");
  script_tag(name:"insight", value:"The glibc packages contain the standard C
libraries used by multiple programs on the system. These packages contain the
standard C and the standard math libraries. Without these two libraries, a Linux
system cannot function properly.

An off-by-one heap-based buffer overflow flaw was found in glibc's internal
__gconv_translit_find() function. An attacker able to make an application
call the iconv_open() function with a specially crafted argument could
possibly use this flaw to execute arbitrary code with the privileges of
that application. (CVE-2014-5119)

A directory traversal flaw was found in the way glibc loaded locale files.
An attacker able to make an application use a specially crafted locale name
value (for example, specified in an LC_* environment variable) could
possibly use this flaw to execute arbitrary code with the privileges of
that application. (CVE-2014-0475)

Red Hat would like to thank Stephane Chazelas for reporting CVE-2014-0475.

All glibc users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.

4. Solution:

Before applying this update, make sure all previously released errata
relevant to your system have been applied.

This update is available via the Red Hat Network. Details on how to use the
Red Hat Network to apply this update are available at the linked references.

5. Bugs fixed:

1102353 - CVE-2014-0475 glibc: directory traversal in LC_* locale handling
1119128 - CVE-2014-5119 glibc: off-by-one error leading to a heap-based buffer overflow flaw in __gconv_translit_find()

6. Package List:

Red Hat Enterprise Linux Desktop (v. 5 client):

Source:
glibc-2.5-118.el5_10.3.src.rpm

i386:
glibc-2.5-118.el5_10.3.i386.rpm
glibc-2.5-118.el5_10.3.i686.rpm
glibc-common-2.5-118.el5_10.3.i386.rpm
glibc-debuginfo-2.5-118.el5_10.3.i386.rpm
glibc-debuginfo-2.5-118.el5_10.3.i686.rpm
glibc-debuginfo-common-2.5-118.el5_10.3.i386.rpm
glibc-devel-2.5-118.el5_10.3.i386.rpm
glibc-headers-2.5-118.el5_10.3.i386.rpm
glibc-utils-2.5-118.el5_10.3.i386.rpm
nscd-2.5-118.el5_10.3.i386.rpm

x86_64:
glibc-2.5-118.el5_10.3.i686.rpm
glibc-2.5-118.el5_10.3.x86_64.rpm
glibc-common-2.5-118.el5_10.3.x86_64.rpm
glibc-debuginfo-2.5-118.el5_10.3.i386.rpm
glibc-debuginfo-2.5-118.el5_10.3.i686.rpm
glibc-debuginfo-2.5-118.el5_10.3.x86_64.rpm
glibc-debuginfo-common-2.5-118.el5_10.3.i386.rpm
glibc-devel-2.5-118.el5_10.3.i386.rpm
glibc-devel-2.5-118.el5_10.3.x86_64.rpm
glibc-headers-2 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"glibc on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-August/020520.html");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/11258");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~55.el7_0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~55.el7_0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~55.el7_0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~55.el7_0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.17~55.el7_0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~55.el7_0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~55.el7_0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
