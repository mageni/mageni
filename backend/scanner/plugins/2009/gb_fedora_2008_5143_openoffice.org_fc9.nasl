###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for openoffice.org FEDORA-2008-5143
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
tag_insight = "OpenOffice.org is an Open Source, community-developed, multi-platform
  office productivity suite.  It includes the key desktop applications,
  such as a word processor, spreadsheet, presentation manager, formula
  editor and drawing program, with a user interface and feature set
  similar to other office suites.  Sophisticated and flexible,
  OpenOffice.org also works transparently with a variety of file
  formats, including Microsoft Office.

  Usage: Simply type &quot;ooffice&quot; to run OpenOffice.org or select the
  requested component (Writer, Calc, Impress, etc.) from your
  desktop menu. On first start a few files will be installed in the
  user's home, if necessary.";

tag_affected = "openoffice.org on Fedora 9";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-June/msg00385.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307687");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-17 16:50:22 +0100 (Tue, 17 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2008-5143");
  script_cve_id("CVE-2008-2152");
  script_name( "Fedora Update for openoffice.org FEDORA-2008-5143");

  script_tag(name:"summary", value:"Check for the Version of openoffice.org");
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

if(release == "FC9")
{

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~2.4.1~17.3.fc9", rls:"FC9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
