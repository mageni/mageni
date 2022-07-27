###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for freetype CESA-2008:0556 centos4 x86_64
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "FreeType is a free, high-quality, portable font engine that can open and
  manage font files, as well as efficiently load, hint and render individual
  glyphs.

  Multiple flaws were discovered in FreeType's Printer Font Binary (PFB)
  font-file format parser. If a user loaded a carefully crafted font-file
  with a program linked against FreeType, it could cause the application to
  crash, or possibly execute arbitrary code. (CVE-2008-1806, CVE-2008-1807,
  CVE-2008-1808)
  
  Note: the flaw in FreeType's TrueType Font (TTF) font-file format parser,
  covered by CVE-2008-1808, did not affect the freetype packages as shipped
  in Red Hat Enterprise Linux 3, 4, and 5, as they are not compiled with TTF
  Byte Code Interpreter (BCI) support.
  
  Users of freetype should upgrade to these updated packages, which contain
  backported patches to resolve these issues.";

tag_affected = "freetype on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-June/015001.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308340");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:40:14 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
  script_name( "CentOS Update for freetype CESA-2008:0556 centos4 x86_64");

  script_tag(name:"summary", value:"Check for the Version of freetype");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.1.9~7.el4.6", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.1.9~7.el4.6", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.1.9~7.el4.6", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype-utils", rpm:"freetype-utils~2.1.9~7.el4.6", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
