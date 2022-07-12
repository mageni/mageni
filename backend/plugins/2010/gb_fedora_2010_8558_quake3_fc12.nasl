###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for quake3 FEDORA-2010-8558
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
tag_insight = "This package contains the enhanced opensource ioquake3 version of the Quake 3
  Arena engine. This engine can be used to play a number of games based on this
  engine, below is an (incomplete list):

  * OpenArena, Free, Open Source Quake3 like game, recommended!
    (packagename: openarena)
  
  * Urban Terror, gratis, but not Open Source FPS best be described as a
    Hollywood tactical shooter, a downloader and installer including an
    application menu entry is available in the urbanterror package.
  
  * World of Padman, gratis, but not Open Source Comic FPS, a downloader and
    installer including an application menu entry is available in the
    worldofpadman package.
  
  * Quake3 Arena, the original! A downloader and installer for the gratis, but
    not Open Source demo, including an application menu entry is available in
    the quake3-demo package.
  
    If you own a copy of quake 3, you will need to copy pak0.pk3 from the
    original CD-ROM and your q3key to /usr/share/quake3/baseq3 or ~/.q3a/baseq3.
    Also copy the pak?.pk3 files from the original 1.32 Quake 3 Arena point
    release there if you have them available or run quake3-update to download
    them for you.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "quake3 on Fedora 12";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-May/041396.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313883");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-05-17 16:00:10 +0200 (Mon, 17 May 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-8558");
  script_name("Fedora Update for quake3 FEDORA-2010-8558");

  script_tag(name: "summary" , value: "Check for the Version of quake3");
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

if(release == "FC12")
{

  if ((res = isrpmvuln(pkg:"quake3", rpm:"quake3~1.36~7.svn1783.fc12", rls:"FC12")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
