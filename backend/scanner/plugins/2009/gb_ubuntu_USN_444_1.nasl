###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_444_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for openoffice.org(2)/-amd64, ia32-libs-openoffice.org vulnerabilities USN-444-1
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
tag_insight = "A stack overflow was discovered in OpenOffice.org's StarCalc parser.  If
  a user were tricked into opening a specially crafted document, a remote
  attacker could execute arbitrary code with user privileges.
  (CVE-2007-0238)

  A flaw was discovered in OpenOffice.org's link handling code.  If a user
  were tricked into clicking a link in a specially crafted document, a
  remote attacker could execute arbitrary shell commands with user
  privileges.  (CVE-2007-0239)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-444-1";
tag_affected = "openoffice.org(2)/-amd64, ia32-libs-openoffice.org vulnerabilities on Ubuntu 5.10 ,
  Ubuntu 6.06 LTS ,
  Ubuntu 6.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-444-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.311585");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:55:18 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-0238", "CVE-2007-0239");
  script_name( "Ubuntu Update for openoffice.org(2)/-amd64, ia32-libs-openoffice.org vulnerabilities USN-444-1");

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

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libmythes-dev", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-base", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-core", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-filter-so52", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-math", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-evolution", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-uno", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-common", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gtk-gnome", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-us", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-base", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-calc", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-draw", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-gnome", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-impress", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-kde", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-math", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-writer", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"2.0.2-2ubuntu12.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"libmythes-dev", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-base", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-core", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-filter-so52", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-math", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-uno", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"broffice.org", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-common", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-filter-mobiledev", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-us", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-crystal", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-default", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-hicontrast", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-industrial", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"2.0.4-0ubuntu5", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU5.10")
{

  if ((res = isdpkgvuln(pkg:"mozilla-openoffice.org", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-base", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-calc", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-core", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-dev", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-draw", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-evolution", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-filter-so52", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-gnome", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-impress", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-kde", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-math", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-officebean", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-writer", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-uno", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-common", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-dev-doc", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-java-common", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-l10n-en-us", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"1.9.129-0.1ubuntu4.3", rls:"UBUNTU5.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
