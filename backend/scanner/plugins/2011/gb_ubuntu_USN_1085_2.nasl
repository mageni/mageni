###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1085_2.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for tiff regression USN-1085-2
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1085-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.840613");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-24 14:29:52 +0100 (Thu, 24 Mar 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2482", "CVE-2010-2595", "CVE-2010-2597", "CVE-2010-2598", "CVE-2010-2630", "CVE-2010-3087", "CVE-2011-0191");
  script_name("Ubuntu Update for tiff regression USN-1085-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(9\.10|6\.06 LTS|10\.04 LTS|8\.04 LTS|10\.10)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1085-2");
  script_tag(name:"affected", value:"tiff regression on Ubuntu 6.06 LTS,
  Ubuntu 8.04 LTS,
  Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1085-1 fixed vulnerabilities in the system TIFF library. The upstream
  fixes were incomplete and created problems for certain CCITTFAX4 files.
  This update fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  Sauli Pahlman discovered that the TIFF library incorrectly handled invalid
  td_stripbytecount fields. If a user or automated system were tricked into
  opening a specially crafted TIFF image, a remote attacker could crash the
  application, leading to a denial of service. This issue only affected
  Ubuntu 10.04 LTS and 10.10. (CVE-2010-2482)

  Sauli Pahlman discovered that the TIFF library incorrectly handled TIFF
  files with an invalid combination of SamplesPerPixel and Photometric
  values. If a user or automated system were tricked into opening a specially
  crafted TIFF image, a remote attacker could crash the application, leading
  to a denial of service. This issue only affected Ubuntu 10.10.
  (CVE-2010-2482)

  Nicolae Ghimbovschi discovered that the TIFF library incorrectly handled
  invalid ReferenceBlackWhite values. If a user or automated system were
  tricked into opening a specially crafted TIFF image, a remote attacker
  could crash the application, leading to a denial of service.
  (CVE-2010-2595)

  Sauli Pahlman discovered that the TIFF library incorrectly handled certain
  default fields. If a user or automated system were tricked into opening a
  specially crafted TIFF image, a remote attacker could crash the
  application, leading to a denial of service. (CVE-2010-2597, CVE-2010-2598)

  It was discovered that the TIFF library incorrectly validated certain
  data types. If a user or automated system were tricked into opening a
  specially crafted TIFF image, a remote attacker could crash the
  application, leading to a denial of service. (CVE-2010-2630)

  It was discovered that the TIFF library incorrectly handled downsampled
  JPEG data. If a user or automated system were tricked into opening a
  specially crafted TIFF image, a remote attacker could execute arbitrary
  code with user privileges, or crash the application, leading to a denial of
  service. This issue only affected Ubuntu 10.04 LTS and 10.10.
  (CVE-2010-3087)

  It was discovered that the TIFF library incorrectly handled certain JPEG
  data. If a user or automated system were tricked into opening a specially
  crafted TIFF image, a remote attacker could execute arbitrary code with
  user privileges, or crash the application, leading to a denial of servi ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.8.2-13ubuntu0.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.8.2-13ubuntu0.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.8.2-13ubuntu0.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.8.2-13ubuntu0.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.8.2-13ubuntu0.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff-doc", ver:"3.8.2-13ubuntu0.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.7.4-1ubuntu3.10", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.7.4-1ubuntu3.10", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.7.4-1ubuntu3.10", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.7.4-1ubuntu3.10", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.7.4-1ubuntu3.10", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.9.2-2ubuntu0.5", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.9.2-2ubuntu0.5", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.2-2ubuntu0.5", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.9.2-2ubuntu0.5", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.9.2-2ubuntu0.5", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff-doc", ver:"3.9.2-2ubuntu0.5", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.8.2-7ubuntu3.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.8.2-7ubuntu3.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.8.2-7ubuntu3.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.8.2-7ubuntu3.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.8.2-7ubuntu3.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.9.4-2ubuntu0.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.9.4-2ubuntu0.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.4-2ubuntu0.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.9.4-2ubuntu0.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.9.4-2ubuntu0.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff-doc", ver:"3.9.4-2ubuntu0.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
