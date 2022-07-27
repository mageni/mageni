###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for tetex CESA-2010:0400 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-May/016661.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880598");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0791", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-3608", "CVE-2009-3609", "CVE-2010-0739", "CVE-2010-0829", "CVE-2010-1440");
  script_name("CentOS Update for tetex CESA-2010:0400 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tetex'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"tetex on CentOS 5");
  script_tag(name:"insight", value:"teTeX is an implementation of TeX. TeX takes a text file and a set of
  formatting commands as input, and creates a typesetter-independent DeVice
  Independent (DVI) file as output.

  Multiple integer overflow flaws were found in the way teTeX processed
  special commands when converting DVI files into PostScript. An attacker
  could create a malicious DVI file that would cause the dvips executable to
  crash or, potentially, execute arbitrary code. (CVE-2010-0739,
  CVE-2010-1440)

  Multiple array index errors were found in the way teTeX converted DVI files
  into the Portable Network Graphics (PNG) format. An attacker could create a
  malicious DVI file that would cause the dvipng executable to crash.
  (CVE-2010-0829)

  teTeX embeds a copy of Xpdf, an open source Portable Document Format (PDF)
  file viewer, to allow adding images in PDF format to the generated PDF
  documents. The following issues affect Xpdf code:

  Multiple integer overflow flaws were found in Xpdf's JBIG2 decoder. If a
  local user generated a PDF file from a TeX document, referencing a
  specially-crafted PDF file, it would cause Xpdf to crash or, potentially,
  execute arbitrary code with the privileges of the user running pdflatex.
  (CVE-2009-0147, CVE-2009-1179)

  Multiple integer overflow flaws were found in Xpdf. If a local user
  generated a PDF file from a TeX document, referencing a specially-crafted
  PDF file, it would cause Xpdf to crash or, potentially, execute arbitrary
  code with the privileges of the user running pdflatex. (CVE-2009-0791,
  CVE-2009-3608, CVE-2009-3609)

  A heap-based buffer overflow flaw was found in Xpdf's JBIG2 decoder. If a
  local user generated a PDF file from a TeX document, referencing a
  specially-crafted PDF file, it would cause Xpdf to crash or, potentially,
  execute arbitrary code with the privileges of the user running pdflatex.
  (CVE-2009-0195)

  Multiple buffer overflow flaws were found in Xpdf's JBIG2 decoder. If a
  local user generated a PDF file from a TeX document, referencing a
  specially-crafted PDF file, it would cause Xpdf to crash or, potentially,
  execute arbitrary code with the privileges of the user running pdflatex.
  (CVE-2009-0146, CVE-2009-1182)

  Multiple flaws were found in Xpdf's JBIG2 decoder that could lead to the
  freeing of arbitrary memory. If a local user generated a PDF file from a
  TeX document, referencing a specially-crafted PDF file, it would cause
  Xpdf to crash or, potentially, execute arbitrary code with the privileges
  of the user running pdflatex. (CVE-2009-0166, CVE-2009-1180)

  Multiple input validati ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"tetex", rpm:"tetex~3.0~33.8.el5_5.5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-afm", rpm:"tetex-afm~3.0~33.8.el5_5.5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-doc", rpm:"tetex-doc~3.0~33.8.el5_5.5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-dvips", rpm:"tetex-dvips~3.0~33.8.el5_5.5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-fonts", rpm:"tetex-fonts~3.0~33.8.el5_5.5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-latex", rpm:"tetex-latex~3.0~33.8.el5_5.5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-xdvi", rpm:"tetex-xdvi~3.0~33.8.el5_5.5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
