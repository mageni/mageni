###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_466_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for freetype vulnerability USN-466-1
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
tag_insight = "Victor Stinner discovered that freetype did not correctly verify the
  number of points in a TrueType font.  If a user were tricked into using
  a specially crafted font, a remote attacker could execute arbitrary code
  with user privileges.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-466-1";
tag_affected = "freetype vulnerability on Ubuntu 6.06 LTS ,
  Ubuntu 6.10 ,
  Ubuntu 7.04";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-466-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.311113");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:55:18 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2007-2754");
  script_name( "Ubuntu Update for freetype vulnerability USN-466-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.2.1-5ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.2.1-5ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.2.1-5ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.1.10-1ubuntu2.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.1.10-1ubuntu2.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.1.10-1ubuntu2.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.2.1-5ubuntu0.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.2.1-5ubuntu0.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.2.1-5ubuntu0.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
