###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for libtool FEDORA-2010-10640
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
tag_insight = "GNU Libtool is a set of shell scripts which automatically configure UNIX and
  UNIX-like systems to generically build shared libraries. Libtool provides a
  consistent, portable interface which simplifies the process of using shared
  libraries.

  If you are developing programs which will use shared libraries, but do not use
  the rest of the GNU Autotools (such as GNU Autoconf and GNU Automake), you
  should install the libtool package.
  
  The libtool package also includes all files needed to integrate the GNU
  Portable Library Tool (libtool) and the GNU Libtool Dynamic Module Loader
  (ltdl) into a package built using the GNU Autotools (including GNU Autoconf
  and GNU Automake).";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "libtool on Fedora 12";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-July/043780.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313014");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-12 11:56:20 +0200 (Mon, 12 Jul 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-10640");
  script_cve_id("CVE-2009-3736", "CVE-2010-0831", "CVE-2010-2322");
  script_name("Fedora Update for libtool FEDORA-2010-10640");

  script_tag(name: "summary" , value: "Check for the Version of libtool");
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

  if ((res = isrpmvuln(pkg:"libtool", rpm:"libtool~2.2.6~18.fc12.1", rls:"FC12")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
