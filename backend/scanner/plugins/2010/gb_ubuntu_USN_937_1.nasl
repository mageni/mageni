###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_937_1.nasl 8187 2017-12-20 07:30:09Z teissa $
#
# Ubuntu Update for texlive-bin vulnerabilities USN-937-1
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
tag_insight = "It was discovered that TeX Live incorrectly handled certain long .bib
  bibliography files. If a user or automated system were tricked into
  processing a specially crafted bib file, an attacker could cause a denial
  of service via application crash. This issue only affected Ubuntu 8.04 LTS,
  9.04 and 9.10. (CVE-2009-1284)

  Marc Schoenefeld, Karel &#352;rot and Ludwig Nussel discovered that TeX Live
  incorrectly handled certain malformed dvi files. If a user or automated
  system were tricked into processing a specially crafted dvi file, an
  attacker could cause a denial of service via application crash, or possibly
  execute arbitrary code with the privileges of the user invoking the
  program. (CVE-2010-0739, CVE-2010-1440)
  
  Dan Rosenberg discovered that TeX Live incorrectly handled certain
  malformed dvi files. If a user or automated system were tricked into
  processing a specially crafted dvi file, an attacker could cause a denial
  of service via application crash, or possibly execute arbitrary code with
  the privileges of the user invoking the program. (CVE-2010-0827)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-937-1";
tag_affected = "texlive-bin vulnerabilities on Ubuntu 8.04 LTS ,
  Ubuntu 9.04 ,
  Ubuntu 9.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-937-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.313339");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-05-07 15:42:01 +0200 (Fri, 07 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1284", "CVE-2010-0739", "CVE-2010-0827", "CVE-2010-1440");
  script_name("Ubuntu Update for texlive-bin vulnerabilities USN-937-1");

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

  if ((res = isdpkgvuln(pkg:"libkpathsea-dev", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkpathsea4", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-base-bin-doc", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-base-bin", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-extra-utils", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-font-utils", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-lang-indic", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-metapost-doc", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-metapost", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-music", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-omega", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-xetex", ver:"2007.dfsg.2-7ubuntu1.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU9.04")
{

  if ((res = isdpkgvuln(pkg:"libkpathsea-dev", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkpathsea4", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-base-bin-doc", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-base-bin", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-extra-utils", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-font-utils", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-lang-indic", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-metapost-doc", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-xetex", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-metapost", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-music", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-omega", ver:"2007.dfsg.2-4ubuntu2.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libkpathsea-dev", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkpathsea4", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-base-bin-doc", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-base-bin", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-extra-utils", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-font-utils", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-lang-indic", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-metapost-doc", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-metapost", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-music", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-omega", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"texlive-xetex", ver:"2007.dfsg.1-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
