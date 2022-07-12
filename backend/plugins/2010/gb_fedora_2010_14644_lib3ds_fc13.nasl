###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for lib3ds FEDORA-2010-14644
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
tag_insight = "lib3ds is a free ANSI-C library for working with the popular &quot;3ds&quot; 3D model
  format.

  Supported platforms include GNU (autoconf, automake, libtool, make, GCC) on
  Unix and Cygwin, and MS Visual C++ 6.0. lib3ds loads and saves Atmosphere
  settings, Background settings, Shadow map settings, Viewport setting,
  Materials, Cameras, Lights, Meshes, Hierarchy, Animation keyframes. It also
  contains useful matrix, vector and quaternion mathematics tools. lib3ds
  usually integrates well with OpenGL. In addition, some diagnostic and
  conversion tools are included.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "lib3ds on Fedora 13";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-September/048324.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314349");
  script_version("$Revision: 8250 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-10-01 08:16:52 +0200 (Fri, 01 Oct 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-14644");
  script_cve_id("CVE-2010-0280");
  script_name("Fedora Update for lib3ds FEDORA-2010-14644");

  script_tag(name: "summary" , value: "Check for the Version of lib3ds");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC13")
{

  if ((res = isrpmvuln(pkg:"lib3ds", rpm:"lib3ds~1.3.0~9.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
