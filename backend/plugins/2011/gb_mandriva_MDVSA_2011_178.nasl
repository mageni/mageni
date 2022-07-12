###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for glibc MDVSA-2011:178 (glibc)
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-11/msg00037.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831500");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-11-28 12:50:20 +0530 (Mon, 28 Nov 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3847", "CVE-2011-0536", "CVE-2010-2898", "CVE-2011-1071",
                "CVE-2010-0296", "CVE-2011-1089", "CVE-2011-1095", "CVE-2011-1659",
                "CVE-2011-2483");
  script_name("Mandriva Update for glibc MDVSA-2011:178 (glibc)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2010\.1)");
  script_tag(name:"affected", value:"glibc on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities was discovered and fixed in glibc:
  Multiple untrusted search path vulnerabilities in elf/dl-object.c in
  certain modified versions of the GNU C Library (aka glibc or libc6),
  including glibc-2.5-49.el5_5.6 and glibc-2.12-1.7.el6_0.3 in Red Hat
  Enterprise Linux, allow local users to gain privileges via a crafted
  dynamic shared object (DSO) in a subdirectory of the current working
  directory during execution of a (1) setuid or (2) setgid program that
  has  in (a) RPATH or (b) RUNPATH.  NOTE: this issue exists because
  of an incorrect fix for CVE-2010-3847 (CVE-2011-0536).

  The GNU C Library (aka glibc or libc6) before 2.12.2 and Embedded GLIBC
  (EGLIBC) allow context-dependent attackers to execute arbitrary code
  or cause a denial of service (memory consumption) via a long UTF8
  string that is used in an fnmatch call, aka a stack extension attack,
  a related issue to CVE-2010-2898, as originally reported for use of
  this library by Google Chrome (CVE-2011-1071).

  The addmntent function in the GNU C Library (aka glibc or libc6) 2.13
  and earlier does not report an error status for failed attempts to
  write to the /etc/mtab file, which makes it easier for local users
  to trigger corruption of this file, as demonstrated by writes from
  a process with a small RLIMIT_FSIZE value, a different vulnerability
  than CVE-2010-0296 (CVE-2011-1089).

  locale/programs/locale.c in locale in the GNU C Library (aka glibc
  or libc6) before 2.13 does not quote its output, which might allow
  local users to gain privileges via a crafted localization environment
  variable, in conjunction with a program that executes a script that
  uses the eval function (CVE-2011-1095).

  Integer overflow in posix/fnmatch.c in the GNU C Library (aka glibc or
  libc6) 2.13 and earlier allows context-dependent attackers to cause a
  denial of service (application crash) via a long UTF8 string that is
  used in an fnmatch call with a crafted pattern argument, a different
  vulnerability than CVE-2011-1071 (CVE-2011-1659).

  crypt_blowfish before 1.1, as used in glibc on certain platforms,
  does not properly handle 8-bit characters, which makes it easier
  for context-dependent attackers to determine a cleartext password by
  leveraging knowledge of a password hash (CVE-2011-2483).

  The updated packages have been patched to correct these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.8~1.20080520.5.8mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.8~1.20080520.5.8mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.8~1.20080520.5.8mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc-pdf", rpm:"glibc-doc-pdf~2.8~1.20080520.5.8mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.8~1.20080520.5.8mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.8~1.20080520.5.8mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.8~1.20080520.5.8mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.8~1.20080520.5.8mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.8~1.20080520.5.8mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.11.1~8.3mnb2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.11.1~8.3mnb2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.11.1~8.3mnb2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc-pdf", rpm:"glibc-doc-pdf~2.11.1~8.3mnb2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.11.1~8.3mnb2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.11.1~8.3mnb2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.11.1~8.3mnb2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.11.1~8.3mnb2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.11.1~8.3mnb2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
