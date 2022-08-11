###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for glibc RHSA-2013:1605-02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871075");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-11-21 10:43:57 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4332");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for glibc RHSA-2013:1605-02");


  script_tag(name:"affected", value:"glibc on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"The glibc packages provide the standard C libraries (libc), POSIX thread
libraries (libpthread), standard math libraries (libm), and the Name Server
Caching Daemon (nscd) used by multiple programs on the system. Without
these libraries, the Linux system cannot function correctly.

Multiple integer overflow flaws, leading to heap-based buffer overflows,
were found in glibc's memory allocator functions (pvalloc, valloc, and
memalign). If an application used such a function, it could cause the
application to crash or, potentially, execute arbitrary code with the
privileges of the user running the application. (CVE-2013-4332)

A flaw was found in the regular expression matching routines that process
multibyte character input. If an application utilized the glibc regular
expression matching mechanism, an attacker could provide specially-crafted
input that, when processed, would cause the application to crash.
(CVE-2013-0242)

It was found that getaddrinfo() did not limit the amount of stack memory
used during name resolution. An attacker able to make an application
resolve an attacker-controlled hostname or IP address could possibly cause
the application to exhaust all stack memory and crash. (CVE-2013-1914)

Among other changes, this update includes an important fix for the
following bug:

  * Due to a defect in the initial release of the getaddrinfo() system call
in Red Hat enterprise Linux 6.0, AF_INET and AF_INET6 queries resolved from
the /etc/hosts file returned queried names as canonical names. This
incorrect behavior is, however, still considered to be the expected
behavior. As a result of a recent change in getaddrinfo(), AF_INET6 queries
started resolving the canonical names correctly. However, this behavior was
unexpected by applications that relied on queries resolved from the
/etc/hosts file, and these applications could thus fail to operate
properly. This update applies a fix ensuring that AF_INET6 queries resolved
from /etc/hosts always return the queried name as canonical. Note that DNS
lookups are resolved properly and always return the correct canonical
names. A proper fix to AF_INET6 queries resolution from /etc/hosts may be
applied in future releases  for now, due to a lack of standard, Red Hat
suggests the first entry in the /etc/hosts file, that applies for the IP
address being resolved, to be considered the canonical entry. (BZ#1022022)

These updated glibc packages also include additional bug fixes and
various enhancements. Space precludes documenting all of these ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-November/msg00026.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.12~1.132.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.12~1.132.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.12~1.132.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo-common", rpm:"glibc-debuginfo-common~2.12~1.132.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.12~1.132.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.12~1.132.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.12~1.132.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.12~1.132.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
