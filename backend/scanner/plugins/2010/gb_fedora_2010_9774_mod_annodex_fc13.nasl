###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mod_annodex FEDORA-2010-9774
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
tag_insight = "mod_annodex provides full support for Annodex.net media. For more details
  about annodex format, see http://www.annodex.net/ &qt >http://www.annodex.net/

  mod_annodex is a handler for type application/x-annodex. It provides the
  following features:
  
          * dynamic generation of Annodex media from CMML files.
  
          * handling of timed query offsets, such as
  
            http://media.example.com/fish.anx?t=npt:01:20.8
          or
            http://media.example.com/fish.anx?id=Preparation
  
          * dynamic retrieval of CMML summaries, if the Accept: header
            prefers type text/x-cmml over application/x-annodex.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "mod_annodex on Fedora 13";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-June/042713.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314096");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-11 13:46:51 +0200 (Fri, 11 Jun 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-9774");
  script_cve_id("CVE-2009-3377");
  script_name("Fedora Update for mod_annodex FEDORA-2010-9774");

  script_tag(name: "summary" , value: "Check for the Version of mod_annodex");
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

  if ((res = isrpmvuln(pkg:"mod_annodex", rpm:"mod_annodex~0.2.2~13.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
