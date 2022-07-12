###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for poppler MDVSA-2011:175 (poppler)
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-11/msg00029.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831494");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-11-18 09:47:30 +0530 (Fri, 18 Nov 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180",
                "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-1187",
                "CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-0791",
                "CVE-2009-3605", "CVE-2009-3606", "CVE-2009-3607", "CVE-2009-3608",
                "CVE-2009-3609", "CVE-2009-3938");
  script_name("Mandriva Update for poppler MDVSA-2011:175 (poppler)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"affected", value:"poppler on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Multiple security vulnerabilities has been discovered and corrected
  in poppler:

  An out-of-bounds reading flaw in the JBIG2 decoder allows remote
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
  via a crafted PDF file, related to (1) glib/poppler-page.cc, (2)
  ArthurOutputDev.cc, (3) CairoOutputDev.cc, (4) GfxState.cc, (5)
  JBIG2Stream.cc, (6) PSO ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"libpoppler3", rpm:"libpoppler3~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib3", rpm:"libpoppler-glib3~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt2", rpm:"libpoppler-qt2~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-3", rpm:"libpoppler-qt4-3~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-devel", rpm:"libpoppler-qt4-devel~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt-devel", rpm:"libpoppler-qt-devel~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler3", rpm:"lib64poppler3~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-devel", rpm:"lib64poppler-devel~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-glib3", rpm:"lib64poppler-glib3~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-glib-devel", rpm:"lib64poppler-glib-devel~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt2", rpm:"lib64poppler-qt2~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt4-3", rpm:"lib64poppler-qt4-3~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt4-devel", rpm:"lib64poppler-qt4-devel~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt-devel", rpm:"lib64poppler-qt-devel~0.8.7~2.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
