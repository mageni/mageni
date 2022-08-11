###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for drakx-kbd-mouse-x11 MDVA-2008:059 (drakx-kbd-mouse-x11)
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
tag_insight = "An updated XFdrake is available that corrects a number of bugs:

  - never write a ModeLine when using the fglrx driver (bug #30934)
  
  - if the EDID gives a valid EISA_ID, a valid 16/10 preferred
  resolution, but no HorizSync/VertRefresh, use a generic flat panel
  HorizSync/VertRefresh (needed for edid.lcd.Elonex-PR600)
  
  - add 800x480 (used on belinea s.book)
  
  - add 1024x600 (used on Samsung Q1Ultra) (bug #37889)
  
  - if the EDID gives a valid 16/10 preferred resolution (even if
  duplicated), but no HorizSync/VertRefresh, use a generic flat panel
  HorizSync/VertRefresh (needed for edid.lcd.dell-inspiron-6400,
  bug #37971)";

tag_affected = "drakx-kbd-mouse-x11 on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-05/msg00010.php");
  script_oid("1.3.6.1.4.1.25623.1.0.307454");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:05:19 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVA", value: "2008:059");
  script_name( "Mandriva Update for drakx-kbd-mouse-x11 MDVA-2008:059 (drakx-kbd-mouse-x11)");

  script_tag(name:"summary", value:"Check for the Version of drakx-kbd-mouse-x11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"drakx-kbd-mouse-x11", rpm:"drakx-kbd-mouse-x11~0.37.3~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
