###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1013_1.nasl 8287 2018-01-04 07:28:11Z teissa $
#
# Ubuntu Update for freetype vulnerabilities USN-1013-1
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
tag_insight = "Marc Schoenefeld discovered that FreeType did not correctly handle certain
  malformed font files. If a user were tricked into using a specially crafted
  font file, a remote attacker could cause FreeType to crash or possibly
  execute arbitrary code with user privileges. This issue only affected
  Ubuntu 6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS. (CVE-2010-3311)

  Chris Evans discovered that FreeType did not correctly handle certain
  malformed TrueType font files. If a user were tricked into using a
  specially crafted TrueType file, a remote attacker could cause FreeType to
  crash or possibly execute arbitrary code with user privileges. This issue
  only affected Ubuntu 8.04 LTS, 9.10, 10.04 LTS and 10.10. (CVE-2010-3814)
  
  It was discovered that FreeType did not correctly handle certain malformed
  TrueType font files. If a user were tricked into using a specially crafted
  TrueType file, a remote attacker could cause FreeType to crash or possibly
  execute arbitrary code with user privileges. (CVE-2010-3855)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1013-1";
tag_affected = "freetype vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 8.04 LTS ,
  Ubuntu 9.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1013-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.313464");
  script_version("$Revision: 8287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-16 14:49:48 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3311", "CVE-2010-3814", "CVE-2010-3855");
  script_name("Ubuntu Update for freetype vulnerabilities USN-1013-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.3.9-5ubuntu0.4", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.3.9-5ubuntu0.4", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.3.9-5ubuntu0.4", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6-udeb", ver:"2.3.9-5ubuntu0.4", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.1.10-1ubuntu2.10", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.1.10-1ubuntu2.10", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.1.10-1ubuntu2.10", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6-udeb", ver:"2.1.10-1ubuntu2.10", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.3.11-1ubuntu2.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.3.11-1ubuntu2.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.3.11-1ubuntu2.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6-udeb", ver:"2.3.11-1ubuntu2.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.3.5-1ubuntu4.8.04.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.3.5-1ubuntu4.8.04.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.3.5-1ubuntu4.8.04.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libfreetype6-udeb", ver:"2.3.5-1ubuntu4.8.04.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
