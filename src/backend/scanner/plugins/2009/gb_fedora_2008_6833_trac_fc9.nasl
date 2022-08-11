###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for trac FEDORA-2008-6833
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
tag_affected = "trac on Fedora 9";
tag_insight = "Trac is an integrated system for managing software projects, an
  enhanced wiki, a flexible web-based issue tracker, and an interface to
  the Subversion revision control system.  At the core of Trac lies an
  integrated wiki and issue/bug database. Using wiki markup, all objects
  managed by Trac can directly link to other issues/bug reports, code
  changesets, documentation and files.  Around the core lies other
  modules, providing additional features and tools to make software
  development more streamlined and effective.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-July/msg01270.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311836");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-17 17:01:32 +0100 (Tue, 17 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name: "FEDORA", value: "2008-6833");
  script_cve_id("CVE-2008-2951", "CVE-2008-3328");
  script_name( "Fedora Update for trac FEDORA-2008-6833");

  script_tag(name:"summary", value:"Check for the Version of trac");
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

if(release == "FC9")
{

  if ((res = isrpmvuln(pkg:"trac", rpm:"trac~0.10.5~1.fc9", rls:"FC9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}