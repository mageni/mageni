###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for xorg-x11-server FEDORA-2007-424
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
tag_insight = "X.Org X11 X server

  ---------------------------------------------------------------------
  
  * Sun Apr  8 2007 Adam Jackson &lt;ajax redhat com&gt; 1.0.1-9.fc5.7
  - xserver-cve-2007-1003.patch: Fix CVE 2007-1003 in XC-MISC extension.
  - xorg-x11-server-1.0.1-intel-bridge-fix.patch: Backport an Intel PCI bridge
    fix from FC6.
  * Tue Jan  9 2007 Adam Jackson &lt;ajax redhat com&gt; 1.0.1-9.fc5.6
  - xorg-xserver-1.0.1-dbe-render.diff: CVE #2006-6101.
  * Fri Jun 30 2006 Mike A. Harris &lt;mharris redhat com&gt; 1.0.1-9.fc5.5
  - Standardize on using lowercase &quot;fcN&quot; in Release field to denote the OS
    release the package is being built for in all erratum from now on, as this
    is the official Fedora packaging guideline recommended way that the new
    'dist' tag uses:  <a  rel= &qt nofollow &qt  href= &qt http://fedoraproject.org/wiki/DistTag &qt >http://fedoraproject.org/wiki/DistTag</a>. (#197266)
  - Remove various rpm spec file macros from the changelog which were
    inadvertently added over time.  (#197281)
  * Mon Jun 26 2006 Mike A. Harris &lt;mharris redhat com&gt; 1.0.1-9.FC5.4
  - Updated build dependency to require mesa-source-6.4.2-6.FC5.3 minimum for
    DRI enabled builds to fix numerous bug reports on x86_64 including (#190245,
    185929,187603,185727,189730)
  - Added xorg-x11-server-1.0.1-setuid.diff to fix setuid bug (#196126)
  - Bump xtrans dependency to &quot;&gt;= 1.0.0-3.2.FC5.0&quot; for setuid fix in xtrans.
  - Added &quot;BuildRequires: freetype-devel &gt;= 2.1.9-1, zlib-devel&quot; so that the
    package will build now in brew/mock for erratum.
  * Fri May 19 2006 Mike A. Harris &lt;mharris redhat com&gt; 1.0.1-9.FC5.3
  - Enable alpha, sparc, sparc64 architectures to be buildable (untested, but
    feel free to submit patches in bugzilla if it does not work right)
  - Add missing SBUS header for sparc architecture (#187357)
  * Fri May  5 2006 Mike A. Harris &lt;mharris redhat com&gt; 1.0.1-9.fc5.2
  - Merge xorg-x11-server-1.0.1-render-tris-CVE-2006-1526.patch security fix
    from 1.0.1-9.fc5.1.1 release from embargoed branch of CVS to FC-5 branch";

tag_affected = "xorg-x11-server on Fedora Core 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-April/msg00027.html");
  script_oid("1.3.6.1.4.1.25623.1.0.310980");
  script_version("$Revision: 6622 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 07:52:50 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:27:46 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2007-424");
  script_cve_id("CVE-2006-1526");
  script_name( "Fedora Update for xorg-x11-server FEDORA-2007-424");

  script_tag(name:"summary", value:"Check for the Version of xorg-x11-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms");
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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/xorg-x11-server-debuginfo", rpm:"x86_64/debug/xorg-x11-server-debuginfo~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xorg-x11-server-sdk", rpm:"x86_64/xorg-x11-server-sdk~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xorg-x11-server-Xdmx", rpm:"x86_64/xorg-x11-server-Xdmx~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xorg-x11-server-Xnest", rpm:"x86_64/xorg-x11-server-Xnest~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xorg-x11-server-Xorg", rpm:"x86_64/xorg-x11-server-Xorg~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xorg-x11-server-Xvfb", rpm:"x86_64/xorg-x11-server-Xvfb~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/xorg-x11-server-debuginfo", rpm:"i386/debug/xorg-x11-server-debuginfo~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xorg-x11-server-Xnest", rpm:"i386/xorg-x11-server-Xnest~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xorg-x11-server-Xdmx", rpm:"i386/xorg-x11-server-Xdmx~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xorg-x11-server-sdk", rpm:"i386/xorg-x11-server-sdk~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xorg-x11-server-Xorg", rpm:"i386/xorg-x11-server-Xorg~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xorg-x11-server-Xvfb", rpm:"i386/xorg-x11-server-Xvfb~1.0.1~9.fc5.7", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
