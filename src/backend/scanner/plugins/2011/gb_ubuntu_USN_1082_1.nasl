###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1082_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for pango1.0 vulnerabilities USN-1082-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1082-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840602");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0421", "CVE-2011-0020", "CVE-2011-0064");
  script_name("Ubuntu Update for pango1.0 vulnerabilities USN-1082-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(9\.10|10\.10|10\.04 LTS|8\.04 LTS)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1082-1");
  script_tag(name:"affected", value:"pango1.0 vulnerabilities on Ubuntu 8.04 LTS,
  Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Marc Schoenefeld discovered that Pango incorrectly handled certain Glyph
  Definition (GDEF) tables. If a user were tricked into displaying text with
  a specially-crafted font, an attacker could cause Pango to crash, resulting
  in a denial of service. This issue only affected Ubuntu 8.04 LTS and 9.10.
  (CVE-2010-0421)

  Dan Rosenberg discovered that Pango incorrectly handled certain FT_Bitmap
  objects. If a user were tricked into displaying text with a specially-
  crafted font, an attacker could cause a denial of service or execute
  arbitrary code with privileges of the user invoking the program. The
  default compiler options for affected releases should reduce the
  vulnerability to a denial of service. (CVE-2011-0020)

  It was discovered that Pango incorrectly handled certain memory
  reallocation failures. If a user were tricked into displaying text in a way
  that would cause a reallocation failure, an attacker could cause a denial
  of service or execute arbitrary code with privileges of the user invoking
  the program. This issue only affected Ubuntu 9.10, 10.04 LTS and 10.10.
  (CVE-2011-0064)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"libpango1.0-0-dbg", ver:"1.26.0-1ubuntu0.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-0", ver:"1.26.0-1ubuntu0.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-dev", ver:"1.26.0-1ubuntu0.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-common", ver:"1.26.0-1ubuntu0.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-doc", ver:"1.26.0-1ubuntu0.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-udeb", ver:"1.26.0-1ubuntu0.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"gir1.0-pango-1.0", ver:"1.28.2-0ubuntu1.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-0-dbg", ver:"1.28.2-0ubuntu1.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-0", ver:"1.28.2-0ubuntu1.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-dev", ver:"1.28.2-0ubuntu1.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-common", ver:"1.28.2-0ubuntu1.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-doc", ver:"1.28.2-0ubuntu1.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-udeb", ver:"1.28.2-0ubuntu1.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"gir1.0-pango-1.0", ver:"1.28.0-0ubuntu2.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-0-dbg", ver:"1.28.0-0ubuntu2.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-0", ver:"1.28.0-0ubuntu2.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-dev", ver:"1.28.0-0ubuntu2.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-common", ver:"1.28.0-0ubuntu2.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-doc", ver:"1.28.0-0ubuntu2.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-udeb", ver:"1.28.0-0ubuntu2.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libpango1.0-0-dbg", ver:"1.20.5-0ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-0", ver:"1.20.5-0ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-dev", ver:"1.20.5-0ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-common", ver:"1.20.5-0ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-doc", ver:"1.20.5-0ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpango1.0-udeb", ver:"1.20.5-0ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
