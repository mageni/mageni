###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for glibc CESA-2012:0125 centos4
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-February/018427.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881217");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:48:09 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0296", "CVE-2010-0830",
                "CVE-2011-1071", "CVE-2011-1089", "CVE-2011-1095", "CVE-2011-1659",
                "CVE-2011-4609");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for glibc CESA-2012:0125 centos4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"glibc on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The glibc packages contain the standard C libraries used by multiple
  programs on the system. These packages contain the standard C and the
  standard math libraries. Without these two libraries, a Linux system cannot
  function properly.

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way the glibc library read timezone files. If a
  carefully-crafted timezone file was loaded by an application linked against
  glibc, it could cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2009-5029)

  A flaw was found in the way the ldd utility identified dynamically linked
  libraries. If an attacker could trick a user into running ldd on a
  malicious binary, it could result in arbitrary code execution with the
  privileges of the user running ldd. (CVE-2009-5064)

  It was discovered that the glibc addmntent() function, used by various
  mount helper utilities, did not sanitize its input properly. A local
  attacker could possibly use this flaw to inject malformed lines into the
  mtab (mounted file systems table) file via certain setuid mount helpers, if
  the attacker were allowed to mount to an arbitrary directory under their
  control. (CVE-2010-0296)

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way the glibc library loaded ELF (Executable and Linking
  Format) files. If a carefully-crafted ELF file was loaded by an
  application linked against glibc, it could cause the application to crash
  or, potentially, execute arbitrary code with the privileges of the user
  running the application. (CVE-2010-0830)

  It was discovered that the glibc fnmatch() function did not properly
  restrict the use of alloca(). If the function was called on sufficiently
  large inputs, it could cause an application using fnmatch() to crash or,
  possibly, execute arbitrary code with the privileges of the application.
  (CVE-2011-1071)

  It was found that the glibc addmntent() function, used by various mount
  helper utilities, did not handle certain errors correctly when updating the
  mtab (mounted file systems table) file. If such utilities had the setuid
  bit set, a local attacker could use this flaw to corrupt the mtab file.
  (CVE-2011-1089)

  It was discovered that the locale command did not produce properly escaped
  output as required by the POSIX specification. If an attacker were able to
  set the locale environment variables in the environment of a script that
  performed shell evaluation on the output of the locale command, ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.3.4~2.57", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.3.4~2.57", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.3.4~2.57", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.3.4~2.57", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.3.4~2.57", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.3.4~2.57", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nptl-devel", rpm:"nptl-devel~2.3.4~2.57", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.3.4~2.57", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
