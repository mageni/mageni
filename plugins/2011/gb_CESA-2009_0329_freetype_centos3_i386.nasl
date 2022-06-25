###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for freetype CESA-2009:0329 centos3 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015887.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880679");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-1861", "CVE-2007-2754", "CVE-2008-1808", "CVE-2009-0946");
  script_name("CentOS Update for freetype CESA-2009:0329 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"freetype on CentOS 3");
  script_tag(name:"insight", value:"FreeType is a free, high-quality, portable font engine that can open and
  manage font files. It also loads, hints, and renders individual glyphs
  efficiently. These packages provide both the FreeType 1 and FreeType 2
  font engines.

  Tavis Ormandy of the Google Security Team discovered several integer
  overflow flaws in the FreeType 2 font engine. If a user loaded a
  carefully-crafted font file with an application linked against FreeType 2,
  it could cause the application to crash or, possibly, execute arbitrary
  code with the privileges of the user running the application.
  (CVE-2009-0946)

  Chris Evans discovered multiple integer overflow flaws in the FreeType font
  engine. If a user loaded a carefully-crafted font file with an application
  linked against FreeType, it could cause the application to crash or,
  possibly, execute arbitrary code with the privileges of the user running
  the application. (CVE-2006-1861)

  An integer overflow flaw was found in the way the FreeType font engine
  processed TrueType Font (TTF) files. If a user loaded a carefully-crafted
  font file with an application linked against FreeType, it could cause the
  application to crash or, possibly, execute arbitrary code with the
  privileges of the user running the application. (CVE-2007-2754)

  A flaw was discovered in the FreeType TTF font-file format parser when the
  TrueType virtual machine Byte Code Interpreter (BCI) is enabled. If a user
  loaded a carefully-crafted font file with an application linked against
  FreeType, it could cause the application to crash or, possibly, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2008-1808)

  The CVE-2008-1808 flaw did not affect the freetype packages as distributed
  in Red Hat Enterprise Linux 3 and 4, as they are not compiled with TrueType
  BCI support. A fix for this flaw has been included in this update as users
  may choose to recompile the freetype packages in order to enable TrueType
  BCI support. Red Hat does not, however, provide support for modified and
  recompiled packages.

  Note: For the FreeType 2 font engine, the CVE-2006-1861, CVE-2007-2754,
  and CVE-2008-1808 flaws were addressed via RHSA-2006:0500, RHSA-2007:0403,
  and RHSA-2008:0556 respectively. This update provides corresponding
  updates for the FreeType 1 font engine, included in the freetype packages
  distributed in Red Hat Enterprise Linux 3 and 4.

  Users are advised to upgrade to these updated packages, which contain
  backported patches to correct these issues. The X server must be restarted
  (log out, then log back in) for this update to take effect.");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.1.4~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.1.4~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.1.4~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype-utils", rpm:"freetype-utils~2.1.4~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
