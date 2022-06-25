###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for glibc RHSA-2015:2199-07
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871503");
  script_version("$Revision: 12380 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:03:48 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:26:16 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2013-7423", "CVE-2015-1472", "CVE-2015-1473", "CVE-2015-1781");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for glibc RHSA-2015:2199-07");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The glibc packages provide the standard C
libraries (libc), POSIX thread libraries (libpthread), standard math libraries
(libm), and the Name Server Caching Daemon (nscd) used by multiple programs on
the system. Without these libraries, the Linux system cannot function correctly.

It was discovered that, under certain circumstances, glibc's getaddrinfo()
function would send DNS queries to random file descriptors. An attacker
could potentially use this flaw to send DNS queries to unintended
recipients, resulting in information disclosure or data loss due to the
application encountering corrupted data. (CVE-2013-7423)

A buffer overflow flaw was found in the way glibc's gethostbyname_r() and
other related functions computed the size of a buffer when passed a
misaligned buffer as input. An attacker able to make an application call
any of these functions with a misaligned buffer could use this flaw to
crash the application or, potentially, execute arbitrary code with the
permissions of the user running the application. (CVE-2015-1781)

A heap-based buffer overflow flaw and a stack overflow flaw were found in
glibc's swscanf() function. An attacker able to make an application call
the swscanf() function could use these flaws to crash that application or,
potentially, execute arbitrary code with the permissions of the user
running the application. (CVE-2015-1472, CVE-2015-1473)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in glibc's _IO_wstr_overflow() function. An attacker able to make an
application call this function could use this flaw to crash that
application or, potentially, execute arbitrary code with the permissions of
the user running the application. (BZ#1195762)

A flaw was found in the way glibc's fnmatch() function processed certain
malformed patterns. An attacker able to make an application call this
function could use this flaw to crash that application. (BZ#1197730)

The CVE-2015-1781 issue was discovered by Arjun Shankar of Red Hat.

These updated glibc packages also include numerous bug fixes and one
enhancement. Space precludes documenting all of these changes in this
advisory. For information on the most significant of these changes, users
are directed to the linked article on the Red Hat Customer Portal.

All glibc users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements.");
  script_tag(name:"affected", value:"glibc on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00031.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  script_xref(name:"URL", value:"https://access.redhat.com/articles/2050743");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~105.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~105.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.17~105.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo-common", rpm:"glibc-debuginfo-common~2.17~105.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~105.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~105.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~105.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~105.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
