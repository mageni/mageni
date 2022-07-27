###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for thunar-volman FEDORA-2007-4368
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
tag_affected = "thunar-volman on Fedora 8";
tag_insight = "The Thunar Volume Manager is an extension for the Thunar file manager, which
  enables automatic management of removable drives and media. For example, if
  thunar-volman is installed and configured properly, and you plug in your
  digital camera, it will automatically launch your preferred photo application
  and import the new pictures from the camera into your photo collection.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-December/msg00568.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306849");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:27:46 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2007-4368");
  script_name( "Fedora Update for thunar-volman FEDORA-2007-4368");

  script_tag(name:"summary", value:"Check for the Version of thunar-volman");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "FC8")
{

  if ((res = isrpmvuln(pkg:"thunar-volman", rpm:"thunar-volman~0.2.0~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunar-volman-debuginfo", rpm:"thunar-volman-debuginfo~0.2.0~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunar-volman", rpm:"thunar-volman~0.2.0~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunar-volman-debuginfo", rpm:"thunar-volman-debuginfo~0.2.0~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunar-volman", rpm:"thunar-volman~0.2.0~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
