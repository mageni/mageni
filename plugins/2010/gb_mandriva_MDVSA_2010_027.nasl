###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kdelibs4 MDVSA-2010:027 (kdelibs4)
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
tag_insight = "Multiple vulnerabilities was discovered and corrected in kdelibs4:

  KDE KSSL in kdelibs 3.5.4, 4.2.4, and 4.3 does not properly handle a
  \'\0\' (NUL) character in a domain name in the Subject Alternative
  Name field of an X.509 certificate, which allows man-in-the-middle
  attackers to spoof arbitrary SSL servers via a crafted certificate
  issued by a legitimate Certification Authority, a related issue to
  CVE-2009-2408 (CVE-2009-2702).
  
  The JavaScript garbage collector in WebKit in Apple Safari before
  4.0, iPhone OS 1.0 through 2.2.1, and iPhone OS for iPod touch 1.1
  through 2.2.1 does not properly handle allocation failures, which
  allows remote attackers to execute arbitrary code or cause a denial
  of service (memory corruption and application crash) via a crafted
  HTML document that triggers write access to an offset of a NULL
  pointer. (CVE-2009-1687).
  
  WebKit in Apple Safari before 4.0.2, KHTML in kdelibs in KDE, QtWebKit
  (aka Qt toolkit), and possibly other products does not properly handle
  numeric character references, which allows remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted HTML document (CVE-2009-1725).
  
  Use-after-free vulnerability in WebKit, as used in Apple Safari
  before 4.0, iPhone OS 1.0 through 2.2.1, iPhone OS for iPod touch 1.1
  through 2.2.1, Google Chrome 1.0.154.53, and possibly other products,
  allows remote attackers to execute arbitrary code or cause a denial
  of service (memory corruption and application crash) by setting an
  unspecified property of an HTML tag that causes child elements to
  be freed and later accessed when an HTML error occurs, related to
  recursion in certain DOM event handlers. (CVE-2009-1690).
  
  WebKit in Apple Safari before 4.0, iPhone OS 1.0 through 2.2.1,
  and iPhone OS for iPod touch 1.1 through 2.2.1 does not initialize a
  pointer during handling of a Cascading Style Sheets (CSS) attr function
  call with a large numerical argument, which allows remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted HTML document (CVE-2009-1698).
  
  KDE Konqueror allows remote attackers to cause a denial of service
  (memory consumption) via a large integer value for the length property
  of a Select object, a related issue to CVE-2009-1692 (CVE-2009-2537).
  
  The gdtoa (aka new dtoa) implementation in gdtoa/misc.c in
  libc in FreeBSD 6.4 and 7.2, NetBSD 5.0, and OpenBSD 4.5 allows
  context-dependent atta ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kdelibs4 on Mandriva Linux 2009.1,
  Mandriva Linux 2009.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-01/msg00077.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314931");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-29 14:09:25 +0100 (Fri, 29 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:027");
  script_cve_id("CVE-2009-2408", "CVE-2009-2702", "CVE-2009-1687", "CVE-2009-1725", "CVE-2009-1690", "CVE-2009-1698", "CVE-2009-1692", "CVE-2009-2537", "CVE-2009-0689", "CVE-2009-0945");
  script_name("Mandriva Update for kdelibs4 MDVSA-2010:027 (kdelibs4)");

  script_tag(name: "summary" , value: "Check for the Version of kdelibs4");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

if(release == "MNDK_2009.1")
{

  if ((res = isrpmvuln(pkg:"kdelibs4-core", rpm:"kdelibs4-core~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-devel", rpm:"kdelibs4-devel~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde3support4", rpm:"libkde3support4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore5", rpm:"libkdecore5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdefakes5", rpm:"libkdefakes5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdesu5", rpm:"libkdesu5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdeui5", rpm:"libkdeui5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdnssd4", rpm:"libkdnssd4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkfile4", rpm:"libkfile4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkhtml5", rpm:"libkhtml5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkimproxy4", rpm:"libkimproxy4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkio5", rpm:"libkio5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkjs4", rpm:"libkjs4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkjsapi4", rpm:"libkjsapi4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkjsembed4", rpm:"libkjsembed4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkmediaplayer4", rpm:"libkmediaplayer4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libknewstuff2_4", rpm:"libknewstuff2_4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libknotifyconfig4", rpm:"libknotifyconfig4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkntlm4", rpm:"libkntlm4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkparts4", rpm:"libkparts4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkpty4", rpm:"libkpty4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkrosscore4", rpm:"libkrosscore4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkrossui4", rpm:"libkrossui4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libktexteditor4", rpm:"libktexteditor4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkunittest4", rpm:"libkunittest4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkutils4", rpm:"libkutils4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnepomuk4", rpm:"libnepomuk4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libplasma3", rpm:"libplasma3~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsolid4", rpm:"libsolid4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libthreadweaver4", rpm:"libthreadweaver4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4", rpm:"kdelibs4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kde3support4", rpm:"lib64kde3support4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdecore5", rpm:"lib64kdecore5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdefakes5", rpm:"lib64kdefakes5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdesu5", rpm:"lib64kdesu5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdeui5", rpm:"lib64kdeui5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdnssd4", rpm:"lib64kdnssd4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kfile4", rpm:"lib64kfile4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64khtml5", rpm:"lib64khtml5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kimproxy4", rpm:"lib64kimproxy4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kio5", rpm:"lib64kio5~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kjs4", rpm:"lib64kjs4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kjsapi4", rpm:"lib64kjsapi4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kjsembed4", rpm:"lib64kjsembed4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kmediaplayer4", rpm:"lib64kmediaplayer4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64knewstuff2_4", rpm:"lib64knewstuff2_4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64knotifyconfig4", rpm:"lib64knotifyconfig4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kntlm4", rpm:"lib64kntlm4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kparts4", rpm:"lib64kparts4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kpty4", rpm:"lib64kpty4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64krosscore4", rpm:"lib64krosscore4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64krossui4", rpm:"lib64krossui4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ktexteditor4", rpm:"lib64ktexteditor4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kunittest4", rpm:"lib64kunittest4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kutils4", rpm:"lib64kutils4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64nepomuk4", rpm:"lib64nepomuk4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64plasma3", rpm:"lib64plasma3~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64solid4", rpm:"lib64solid4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64threadweaver4", rpm:"lib64threadweaver4~4.2.4~0.8mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
