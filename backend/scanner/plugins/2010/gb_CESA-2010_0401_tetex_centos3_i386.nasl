###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for tetex CESA-2010:0401 centos3 i386
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
  
  Multiple integer overflow flaws were found in Xpdf. If a local user
  generated a PDF file from a TeX document, referencing a specially-crafted
  PDF file, it would cause Xpdf to crash or, potentially, execute arbitrary
  code with the privileges of the user running pdflatex. (CVE-2009-0791,
  CVE-2009-3609)
  
  All users of tetex are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "tetex on CentOS 3";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-May/016633.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314377");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-17 16:00:10 +0200 (Mon, 17 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2007-5935", "CVE-2009-0791", "CVE-2009-3609", "CVE-2010-0739", "CVE-2010-0827", "CVE-2010-1440");
  script_name("CentOS Update for tetex CESA-2010:0401 centos3 i386");

  script_tag(name: "summary" , value: "Check for the Version of tetex");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"tetex", rpm:"tetex~1.0.7~67.19", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-afm", rpm:"tetex-afm~1.0.7~67.19", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-doc", rpm:"tetex-doc~1.0.7~67.19", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-dvips", rpm:"tetex-dvips~1.0.7~67.19", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-fonts", rpm:"tetex-fonts~1.0.7~67.19", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-latex", rpm:"tetex-latex~1.0.7~67.19", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-xdvi", rpm:"tetex-xdvi~1.0.7~67.19", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
