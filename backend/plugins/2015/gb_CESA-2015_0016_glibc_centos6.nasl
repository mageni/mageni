###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for glibc CESA-2015:0016 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882090");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-01-23 12:56:20 +0100 (Fri, 23 Jan 2015)");
  script_cve_id("CVE-2014-6040", "CVE-2014-7817");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for glibc CESA-2015:0016 centos6");
  script_tag(name:"summary", value:"Check the version of glibc");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The glibc packages provide the standard C libraries (libc), POSIX thread
libraries (libpthread), standard math libraries (libm), and the Name Server
Caching Daemon (nscd) used by multiple programs on the system. Without
these libraries, the Linux system cannot function correctly.

An out-of-bounds read flaw was found in the way glibc's iconv() function
converted certain encoded data to UTF-8. An attacker able to make an
application call the iconv() function with a specially crafted argument
could use this flaw to crash that application. (CVE-2014-6040)

It was found that the wordexp() function would perform command substitution
even when the WRDE_NOCMD flag was specified. An attacker able to provide
specially crafted input to an application using the wordexp() function, and
not sanitizing the input correctly, could potentially use this flaw to
execute arbitrary commands with the credentials of the user running that
application. (CVE-2014-7817)

The CVE-2014-7817 issue was discovered by Tim Waugh of the Red Hat
Developer Experience Team.

This update also fixes the following bugs:

  * Previously, when an address lookup using the getaddrinfo() function for
the AF_UNSPEC value was performed on a defective DNS server, the server in
some cases responded with a valid response for the A record, but a referral
response for the AAAA record, which resulted in a lookup failure. A prior
update was implemented for getaddrinfo() to return the valid response, but
it contained a typographical error, due to which the lookup could under
some circumstances still fail. This error has been corrected and
getaddrinfo() now returns a valid response in the described circumstances.
(BZ#1172023)

  * An error in the dlopen() library function previously caused recursive
calls to dlopen() to terminate unexpectedly or to abort with a library
assertion. This error has been fixed and recursive calls to dlopen() no
longer crash or abort. (BZ#1173469)

All glibc users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"glibc on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-January/020863.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.12~1.149.el6_6.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.12~1.149.el6_6.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.12~1.149.el6_6.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.12~1.149.el6_6.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.12~1.149.el6_6.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.12~1.149.el6_6.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.12~1.149.el6_6.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}