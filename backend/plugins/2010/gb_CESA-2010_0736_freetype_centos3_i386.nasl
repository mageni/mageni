###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for freetype CESA-2010:0736 centos3 i386
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
tag_insight = "FreeType is a free, high-quality, portable font engine that can open and
  manage font files. It also loads, hints, and renders individual glyphs
  efficiently. The freetype packages for Red Hat Enterprise Linux 3 provide
  both the FreeType 1 and FreeType 2 font engines.

  It was discovered that the FreeType font rendering engine improperly
  validated certain position values when processing input streams. If a user
  loaded a specially-crafted font file with an application linked against
  FreeType, and the relevant font glyphs were subsequently rendered with the
  X FreeType library (libXft), it could trigger a heap-based buffer overflow
  in the libXft library, causing the application to crash or, possibly,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2010-3311)
  
  An array index error was found in the way the FreeType font rendering
  engine processed certain PostScript Type 42 font files. If a user loaded a
  specially-crafted font file with an application linked against FreeType, it
  could cause the application to crash or, possibly, execute arbitrary code
  with the privileges of the user running the application. (CVE-2010-2806)
  
  A stack overflow flaw was found in the way the FreeType font rendering
  engine processed PostScript Type 1 font files that contain nested Standard
  Encoding Accented Character (seac) calls. If a user loaded a
  specially-crafted font file with an application linked against FreeType, it
  could cause the application to crash. (CVE-2010-3054)
  
  Note: All of the issues in this erratum only affect the FreeType 2 font
  engine.
  
  Users are advised to upgrade to these updated packages, which contain
  backported patches to correct these issues. The X server must be restarted
  (log out, then log back in) for this update to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "freetype on CentOS 3";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-October/017037.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314922");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-19 15:54:15 +0200 (Tue, 19 Oct 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2806", "CVE-2010-3054", "CVE-2010-3311");
  script_name("CentOS Update for freetype CESA-2010:0736 centos3 i386");

  script_tag(name: "summary" , value: "Check for the Version of freetype");
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

  if ((res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.1.4~18.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.1.4~18.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.1.4~18.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype-utils", rpm:"freetype-utils~2.1.4~18.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
