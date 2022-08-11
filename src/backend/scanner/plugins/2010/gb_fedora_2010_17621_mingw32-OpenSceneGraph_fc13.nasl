###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mingw32-OpenSceneGraph FEDORA-2010-17621
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
tag_insight = "The OpenSceneGraph is an OpenSource, cross platform graphics toolkit for the
  development of high performance graphics applications such as flight
  simulators, games, virtual reality and scientific visualization.
  Based around the concept of a SceneGraph, it provides an object oriented
  framework on top of OpenGL freeing the developer from implementing and
  optimizing low level graphics calls, and provides many additional utilities
  for rapid development of graphics applications.

  %{_mingw32_description}
  
  
  %{_mingw32_debug_package}";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "mingw32-OpenSceneGraph on Fedora 13";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-November/051198.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314621");
  script_version("$Revision: 8266 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-23 15:30:07 +0100 (Tue, 23 Nov 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-17621");
  script_cve_id("CVE-2010-0280");
  script_name("Fedora Update for mingw32-OpenSceneGraph FEDORA-2010-17621");

  script_tag(name: "summary" , value: "Check for the Version of mingw32-OpenSceneGraph");
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

  if ((res = isrpmvuln(pkg:"mingw32-OpenSceneGraph", rpm:"mingw32-OpenSceneGraph~2.8.2~3.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
