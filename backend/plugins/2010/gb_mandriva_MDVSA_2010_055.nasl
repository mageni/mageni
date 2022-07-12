###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for poppler MDVSA-2010:055 (poppler)
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
tag_insight = "An out-of-bounds reading flaw in the JBIG2 decoder allows remote
  attackers to cause a denial of service (crash) via a crafted PDF file
  (CVE-2009-0799).

  Multiple input validation flaws in the JBIG2 decoder allows
  remote attackers to execute arbitrary code via a crafted PDF file
  (CVE-2009-0800).
  
  An integer overflow in the JBIG2 decoder allows remote attackers to
  execute arbitrary code via a crafted PDF file (CVE-2009-1179).
  
  A free of invalid data flaw in the JBIG2 decoder allows remote
  attackers to execute arbitrary code via a crafted PDF (CVE-2009-1180).
  
  A NULL pointer dereference flaw in the JBIG2 decoder allows remote
  attackers to cause denial of service (crash) via a crafted PDF file
  (CVE-2009-1181).
  
  Multiple buffer overflows in the JBIG2 MMR decoder allows remote
  attackers to cause denial of service or to execute arbitrary code
  via a crafted PDF file (CVE-2009-1182, CVE-2009-1183).
  
  An integer overflow in the JBIG2 decoding feature allows remote
  attackers to cause a denial of service (crash) and possibly execute
  arbitrary code via vectors related to CairoOutputDev (CVE-2009-1187).
  
  An integer overflow in the JBIG2 decoding feature allows remote
  attackers to execute arbitrary code or cause a denial of service
  (application crash) via a crafted PDF document (CVE-2009-1188).
  
  Integer overflow in the SplashBitmap::SplashBitmap function in Xpdf 3.x
  before 3.02pl4 and Poppler before 0.12.1 might allow remote attackers
  to execute arbitrary code via a crafted PDF document that triggers a
  heap-based buffer overflow.  NOTE: some of these details are obtained
  from third party information.  NOTE: this issue reportedly exists
  because of an incomplete fix for CVE-2009-1188 (CVE-2009-3603).
  
  The Splash::drawImage function in Splash.cc in Xpdf 2.x and 3.x
  before 3.02pl4, and Poppler 0.x, as used in GPdf and kdegraphics KPDF,
  does not properly allocate memory, which allows remote attackers to
  cause a denial of service (application crash) or possibly execute
  arbitrary code via a crafted PDF document that triggers a NULL pointer
  dereference or a heap-based buffer overflow (CVE-2009-3604).
  
  Multiple integer overflows allow remote attackers to cause a denial
  of service (application crash) or possibly execute arbitrary code
  via a crafted PDF file, related to (1) glib/poppler-page.cc; (2)
  ArthurOutputDev.cc, (3) CairoOutputDev.cc, (4) GfxState.cc, (5)
  JBIG2Stream.cc, (6) PSOutputDev.cc, and (7) SplashOutputDev.cc
  in poppler/; and (8) SplashBitmap.cc, (9) Splash.cc, and (1 ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "poppler on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-03/msg00015.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314785");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-12 17:02:32 +0100 (Fri, 12 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:055");
  script_cve_id("CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-1187", "CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-0791", "CVE-2009-3605", "CVE-2009-3606", "CVE-2009-3607", "CVE-2009-3608", "CVE-2009-3609", "CVE-2009-3938");
  script_name("Mandriva Update for poppler MDVSA-2010:055 (poppler)");

  script_tag(name: "summary" , value: "Check for the Version of poppler");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"libpoppler3", rpm:"libpoppler3~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib3", rpm:"libpoppler-glib3~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt2", rpm:"libpoppler-qt2~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-3", rpm:"libpoppler-qt4-3~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-devel", rpm:"libpoppler-qt4-devel~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt-devel", rpm:"libpoppler-qt-devel~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler3", rpm:"lib64poppler3~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-devel", rpm:"lib64poppler-devel~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-glib3", rpm:"lib64poppler-glib3~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-glib-devel", rpm:"lib64poppler-glib-devel~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt2", rpm:"lib64poppler-qt2~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt4-3", rpm:"lib64poppler-qt4-3~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt4-devel", rpm:"lib64poppler-qt4-devel~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt-devel", rpm:"lib64poppler-qt-devel~0.8.7~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
