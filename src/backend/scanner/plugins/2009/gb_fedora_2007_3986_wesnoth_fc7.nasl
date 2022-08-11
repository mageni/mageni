###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for wesnoth FEDORA-2007-3986
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
tag_insight = "The Battle for Wesnoth is a turn-based strategy game with a fantasy theme.

  Build up a great army, gradually turning raw recruits into hardened
  veterans. In later games, recall your toughest warriors and form a deadly
  host against whom none can stand. Choose units from a large pool of
  specialists, and hand-pick a force with the right strengths to fight well
  on different terrains against all manner of opposition.
  
  Fight to regain the throne of Wesnoth, of which you are the legitimate
  heir, or use your dread power over the Undead to dominate the land of
  mortals, or lead your glorious Orcish tribe to victory against the humans
  who dared despoil your lands. Wesnoth has many different sagas waiting to
  be played out. You can create your own custom units, and write your own
  scenarios--or even full-blown campaigns. You can also challenge your
  friends--or strangers--and fight multi-player epic fantasy battles.";

tag_affected = "wesnoth on Fedora 7";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-December/msg00004.html");
  script_oid("1.3.6.1.4.1.25623.1.0.309193");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:23:18 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_xref(name: "FEDORA", value: "2007-3986");
  script_cve_id("CVE-2007-5742", "CVE-2007-3917");
  script_name( "Fedora Update for wesnoth FEDORA-2007-3986");

  script_tag(name:"summary", value:"Check for the Version of wesnoth");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"wesnoth", rpm:"wesnoth~1.2.8~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wesnoth-tools", rpm:"wesnoth-tools~1.2.8~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wesnoth-debuginfo", rpm:"wesnoth-debuginfo~1.2.8~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wesnoth-server", rpm:"wesnoth-server~1.2.8~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wesnoth", rpm:"wesnoth~1.2.8~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wesnoth-debuginfo", rpm:"wesnoth-debuginfo~1.2.8~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wesnoth-tools", rpm:"wesnoth-tools~1.2.8~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wesnoth", rpm:"wesnoth~1.2.8~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wesnoth-server", rpm:"wesnoth-server~1.2.8~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
