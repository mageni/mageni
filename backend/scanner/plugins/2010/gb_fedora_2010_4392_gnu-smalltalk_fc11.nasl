###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for gnu-smalltalk FEDORA-2010-4392
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
tag_insight = "GNU Smalltalk is an implementation that closely follows the
  Smalltalk-80 language as described in the book `Smalltalk-80: the
  Language and its Implementation' by Adele Goldberg and David Robson.
  The Smalltalk programming language is an object oriented programming
  language.

  Unlike other Smalltalks (including Smalltalk-80), GNU Smalltalk
  emphasizes Smalltalk's rapid prototyping features rather than the
  graphical and easy-to-use nature of the programming environment.
  
  Therefore, even though we have a nice GUI environment including a class
  browser, the goal of the GNU Smalltalk project is currently to produce a
  complete system to be used to write your scripts in a clear, aesthetically
  pleasing, and philosophically appealing programming language.";

tag_affected = "gnu-smalltalk on Fedora 11";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-March/037654.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313901");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-22 11:34:53 +0100 (Mon, 22 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-4392");
  script_cve_id("CVE-2009-3736");
  script_name("Fedora Update for gnu-smalltalk FEDORA-2010-4392");

  script_tag(name: "summary" , value: "Check for the Version of gnu-smalltalk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "FC11")
{

  if ((res = isrpmvuln(pkg:"gnu-smalltalk", rpm:"gnu-smalltalk~3.1~8.fc11", rls:"FC11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
