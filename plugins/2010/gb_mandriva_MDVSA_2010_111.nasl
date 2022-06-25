###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for glibc MDVSA-2010:111 (glibc)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "Multiple vulnerabilities was discovered and fixed in glibc:

  Multiple integer overflows in the strfmon implementation in
  the GNU C Library (aka glibc or libc6) 2.10.1 and earlier allow
  context-dependent attackers to cause a denial of service (memory
  consumption or application crash) via a crafted format string, as
  demonstrated by a crafted first argument to the money_format function
  in PHP, a related issue to CVE-2008-1391 (CVE-2009-4880).
  
  Integer overflow in the __vstrfmon_l function in stdlib/strfmon_l.c
  in the strfmon implementation in the GNU C Library (aka glibc or
  libc6) before 2.10.1 allows context-dependent attackers to cause a
  denial of service (application crash) via a crafted format string,
  as demonstrated by the %99999999999999999999n string, a related issue
  to CVE-2008-1391 (CVE-2009-4881).
  
  nis/nss_nis/nis-pwd.c in the GNU C Library (aka glibc or libc6)
  2.7 and Embedded GLIBC (EGLIBC) 2.10.2 adds information from the
  passwd.adjunct.byname map to entries in the passwd map, which allows
  remote attackers to obtain the encrypted passwords of NIS accounts
  by calling the getpwnam function (CVE-2010-0015).
  
  The encode_name macro in misc/mntent_r.c in the GNU C Library (aka
  glibc or libc6) 2.11.1 and earlier, as used by ncpmount and mount.cifs,
  does not properly handle newline characters in mountpoint names, which
  allows local users to cause a denial of service (mtab corruption),
  or possibly modify mount options and gain privileges, via a crafted
  mount request (CVE-2010-0296).
  
  Integer signedness error in the elf_get_dynamic_info function
  in elf/dynamic-link.h in ld.so in the GNU C Library (aka glibc or
  libc6) 2.0.1 through 2.11.1, when the --verify option is used, allows
  user-assisted remote attackers to execute arbitrary code via a crafted
  ELF program with a negative value for a certain d_tag structure member
  in the ELF header (CVE-2010-0830).
  
  Packages for 2008.0 and 2009.0 are provided as of the Extended
  Maintenance Program. Please visit this link to learn more:
  http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=490
  
  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "glibc on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2009.1,
  Mandriva Linux 2009.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-06/msg00005.php");
  script_oid("1.3.6.1.4.1.25623.1.0.312853");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-11 13:46:51 +0200 (Fri, 11 Jun 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2010:111");
  script_cve_id("CVE-2008-1391", "CVE-2009-4880", "CVE-2009-4881", "CVE-2010-0015", "CVE-2010-0296", "CVE-2010-0830");
  script_name("Mandriva Update for glibc MDVSA-2010:111 (glibc)");

  script_tag(name: "summary" , value: "Check for the Version of glibc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.6.1~4.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.6.1~4.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.6.1~4.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc-pdf", rpm:"glibc-doc-pdf~2.6.1~4.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.6.1~4.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.6.1~4.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.6.1~4.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.6.1~4.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.6.1~4.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.8~1.20080520.5.5mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.8~1.20080520.5.5mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.8~1.20080520.5.5mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc-pdf", rpm:"glibc-doc-pdf~2.8~1.20080520.5.5mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.8~1.20080520.5.5mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.8~1.20080520.5.5mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.8~1.20080520.5.5mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.8~1.20080520.5.5mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.8~1.20080520.5.5mnb2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.1")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.9~0.20081113.5.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.9~0.20081113.5.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.9~0.20081113.5.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc-pdf", rpm:"glibc-doc-pdf~2.9~0.20081113.5.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.9~0.20081113.5.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.9~0.20081113.5.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.9~0.20081113.5.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.9~0.20081113.5.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.9~0.20081113.5.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.8~1.20080520.5.5mnb2", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.8~1.20080520.5.5mnb2", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.8~1.20080520.5.5mnb2", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc-pdf", rpm:"glibc-doc-pdf~2.8~1.20080520.5.5mnb2", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.8~1.20080520.5.5mnb2", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.8~1.20080520.5.5mnb2", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.8~1.20080520.5.5mnb2", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.8~1.20080520.5.5mnb2", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.8~1.20080520.5.5mnb2", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
