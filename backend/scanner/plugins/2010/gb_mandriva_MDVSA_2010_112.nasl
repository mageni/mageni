###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for glibc MDVSA-2010:112 (glibc)
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
  
  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "glibc on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-06/msg00006.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313914");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-06-11 13:46:51 +0200 (Fri, 11 Jun 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2010:112");
  script_cve_id("CVE-2008-1391", "CVE-2009-4880", "CVE-2010-0015", "CVE-2010-0296", "CVE-2010-0830");
  script_name("Mandriva Update for glibc MDVSA-2010:112 (glibc)");

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

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.10.1~6.5mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.10.1~6.5mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.10.1~6.5mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-doc-pdf", rpm:"glibc-doc-pdf~2.10.1~6.5mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.10.1~6.5mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.10.1~6.5mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.10.1~6.5mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.10.1~6.5mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.10.1~6.5mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
