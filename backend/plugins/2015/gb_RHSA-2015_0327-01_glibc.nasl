###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for glibc RHSA-2015:0327-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871331");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 06:50:44 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2014-6040", "CVE-2014-8121");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for glibc RHSA-2015:0327-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The glibc packages provide the standard C libraries (libc), POSIX thread
libraries (libpthread), standard math libraries (libm), and the Name Server
Caching Daemon (nscd) used by multiple programs on the system. Without
these libraries, the Linux system cannot function correctly.

An out-of-bounds read flaw was found in the way glibc's iconv() function
converted certain encoded data to UTF-8. An attacker able to make an
application call the iconv() function with a specially crafted argument
could use this flaw to crash that application. (CVE-2014-6040)

It was found that the files back end of Name Service Switch (NSS) did not
isolate iteration over an entire database from key-based look-up API calls.
An application performing look-ups on a database while iterating over it
could enter an infinite loop, leading to a denial of service.
(CVE-2014-8121)

This update also fixes the following bugs:

  * Due to problems with buffer extension and reallocation, the nscd daemon
terminated unexpectedly with a segmentation fault when processing long
netgroup entries. With this update, the handling of long netgroup entries
has been corrected and nscd no longer crashes in the described scenario.
(BZ#1138520)

  * If a file opened in append mode was truncated with the ftruncate()
function, a subsequent ftell() call could incorrectly modify the file
offset. This update ensures that ftell() modifies the stream state only
when it is in append mode and the buffer for the stream is not empty.
(BZ#1156331)

  * A defect in the C library headers caused builds with older compilers to
generate incorrect code for the btowc() function in the older compatibility
C++ standard library. Applications calling btowc() in the compatibility C++
standard library became unresponsive. With this update, the C library
headers have been corrected, and the compatibility C++ standard library
shipped with Red Hat Enterprise Linux has been rebuilt. Applications that
rely on the compatibility C++ standard library no longer hang when calling
btowc(). (BZ#1120490)

  * Previously, when using netgroups and the nscd daemon was set up to cache
netgroup information, the sudo utility denied access to valid users. The
bug in nscd has been fixed, and sudo now works in netgroups as
expected. (BZ#1080766)

Users of glibc are advised to upgrade to these updated packages, which fix
these issues.");
  script_tag(name:"affected", value:"glibc on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-March/msg00021.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~78.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~78.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.17~78.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo-common", rpm:"glibc-debuginfo-common~2.17~78.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~78.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~78.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~78.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~78.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
