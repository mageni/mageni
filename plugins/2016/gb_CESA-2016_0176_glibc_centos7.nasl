###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for glibc CESA-2016:0176 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882399");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-02-17 06:27:38 +0100 (Wed, 17 Feb 2016)");
  script_cve_id("CVE-2015-5229", "CVE-2015-7547");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for glibc CESA-2016:0176 centos7");
  script_tag(name:"summary", value:"Check the version of glibc");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The glibc packages provide the standard C
libraries (libc), POSIX  thread libraries (libpthread), standard math libraries
(libm), and the  name service cache daemon (nscd) used by multiple programs on
the  system. Without these libraries, the Linux system cannot function
correctly.

A stack-based buffer overflow was found in the way the libresolv library
performed dual A/AAAA DNS queries. A remote attacker could create a
specially crafted DNS response which could cause libresolv to crash or,
potentially, execute code with the permissions of the user running the
library. Note: this issue is only exposed when libresolv is called from the
nss_dns NSS service module. (CVE-2015-7547)

It was discovered that the calloc implementation in glibc could return
memory areas which contain non-zero bytes. This could result in unexpected
application behavior such as hangs or crashes. (CVE-2015-5229)

The CVE-2015-7547 issue was discovered by the Google Security Team and Red
Hat. Red Hat would like to thank Jeff Layton for reporting the
CVE-2015-5229 issue.

This update also fixes the following bugs:

  * The existing implementation of the 'free' function causes all memory
pools beyond the first to return freed memory directly to the operating
system as quickly as possible. This can result in performance degradation
when the rate of free calls is very high. The first memory pool (the main
pool) does provide a method to rate limit the returns via M_TRIM_THRESHOLD,
but this method is not available to subsequent memory pools.

With this update, the M_TRIM_THRESHOLD method is extended to apply to all
memory pools, which improves performance for threads with very high amounts
of free calls and limits the number of 'madvise' system calls. The change
also increases the total transient memory usage by processes because the
trim threshold must be reached before memory can be freed.

To return to the previous behavior, you can either set M_TRIM_THRESHOLD
using the 'mallopt' function, or set the MALLOC_TRIM_THRESHOLD environment
variable to 0. (BZ#1298930)

  * On the little-endian variant of 64-bit IBM Power Systems (ppc64le), a bug
in the dynamic loader could cause applications compiled with profiling
enabled to fail to start with the error 'monstartup: out of memory'.
The bug has been corrected and applications compiled for profiling now
start correctly. (BZ#1298956)

All glibc users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"glibc on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-February/021672.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~106.el7_2.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~106.el7_2.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~106.el7_2.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~106.el7_2.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.17~106.el7_2.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~106.el7_2.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~106.el7_2.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
