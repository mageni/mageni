###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for tetex RHSA-2010:0399-01
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
tag_insight = "teTeX is an implementation of TeX. TeX takes a text file and a set of
  formatting commands as input, and creates a typesetter-independent DeVice
  Independent (DVI) file as output.

  A buffer overflow flaw was found in the way teTeX processed virtual font
  files when converting DVI files into PostScript. An attacker could create a
  malicious DVI file that would cause the dvips executable to crash or,
  potentially, execute arbitrary code. (CVE-2010-0827)
  
  Multiple integer overflow flaws were found in the way teTeX processed
  special commands when converting DVI files into PostScript. An attacker
  could create a malicious DVI file that would cause the dvips executable to
  crash or, potentially, execute arbitrary code. (CVE-2010-0739,
  CVE-2010-1440)
  
  A stack-based buffer overflow flaw was found in the way teTeX processed DVI
  files containing HyperTeX references with long titles, when converting them
  into PostScript. An attacker could create a malicious DVI file that would
  cause the dvips executable to crash. (CVE-2007-5935)
  
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
  CVE-2009-3609)
  
  A heap-based buffer overflow flaw was found in Xpdf's JBIG2 decoder. If a
  local user generated a PDF file from a TeX document, referencing a
  specially-crafted PDF file, it would cause Xpdf to crash or, potentially,
  execute arbitrary code with the privileges of the user running pdflatex.
  (CVE-2009-0195)
  
  Multiple buffer overflow flaws were found in Xpdf's JBIG2 decoder. If a
  local user generated a PDF file from a TeX document, referencing a
  specially-crafted PDF file, it would cause Xpdf to crash or, potentially,
  execute arbitrary code with the privileges of the user running pdflatex.
  (C ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "tetex on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-May/msg00004.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313431");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-07 15:42:01 +0200 (Fri, 07 May 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2010:0399-01");
  script_cve_id("CVE-2007-5935", "CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0791", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-3609", "CVE-2010-0739", "CVE-2010-0827", "CVE-2010-1440");
  script_name("RedHat Update for tetex RHSA-2010:0399-01");

  script_tag(name: "summary" , value: "Check for the Version of tetex");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"tetex", rpm:"tetex~2.0.2~22.0.1.EL4.16", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-afm", rpm:"tetex-afm~2.0.2~22.0.1.EL4.16", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-debuginfo", rpm:"tetex-debuginfo~2.0.2~22.0.1.EL4.16", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-doc", rpm:"tetex-doc~2.0.2~22.0.1.EL4.16", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-dvips", rpm:"tetex-dvips~2.0.2~22.0.1.EL4.16", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-fonts", rpm:"tetex-fonts~2.0.2~22.0.1.EL4.16", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-latex", rpm:"tetex-latex~2.0.2~22.0.1.EL4.16", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-xdvi", rpm:"tetex-xdvi~2.0.2~22.0.1.EL4.16", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
