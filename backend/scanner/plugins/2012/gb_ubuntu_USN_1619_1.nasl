###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1619_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for openjdk-7 USN-1619-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1619-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841202");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-10-29 11:03:54 +0530 (Mon, 29 Oct 2012)");
  script_cve_id("CVE-2012-3216", "CVE-2012-5069", "CVE-2012-5072", "CVE-2012-5075",
                "CVE-2012-5077", "CVE-2012-5085", "CVE-2012-4416", "CVE-2012-5071",
                "CVE-2012-1531", "CVE-2012-1532", "CVE-2012-1533", "CVE-2012-3143",
                "CVE-2012-3159", "CVE-2012-5068", "CVE-2012-5083", "CVE-2012-5084",
                "CVE-2012-5086", "CVE-2012-5089", "CVE-2012-5067", "CVE-2012-5070",
                "CVE-2012-5073", "CVE-2012-5079", "CVE-2012-5074", "CVE-2012-5076",
                "CVE-2012-5087", "CVE-2012-5088", "CVE-2012-5081");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for openjdk-7 USN-1619-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|12\.04 LTS|11\.10|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1619-1");
  script_tag(name:"affected", value:"openjdk-7 on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Several information disclosure vulnerabilities were discovered in the
  OpenJDK JRE. (CVE-2012-3216, CVE-2012-5069, CVE-2012-5072, CVE-2012-5075,
  CVE-2012-5077, CVE-2012-5085)

  Vulnerabilities were discovered in the OpenJDK JRE related to information
  disclosure and data integrity. (CVE-2012-4416, CVE-2012-5071)

  Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure and data integrity. An attacker could exploit these
  to cause a denial of service. (CVE-2012-1531, CVE-2012-1532, CVE-2012-1533,
  CVE-2012-3143, CVE-2012-3159, CVE-2012-5068, CVE-2012-5083, CVE-2012-5084,
  CVE-2012-5086, CVE-2012-5089)

  Information disclosure vulnerabilities were discovered in the OpenJDK JRE.
  These issues only affected Ubuntu 12.10. (CVE-2012-5067, CVE-2012-5070)

  Vulnerabilities were discovered in the OpenJDK JRE related to data
  integrity. (CVE-2012-5073, CVE-2012-5079)

  A vulnerability was discovered in the OpenJDK JRE related to information
  disclosure and data integrity. This issue only affected Ubuntu 12.10.
  (CVE-2012-5074)

  Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure and data integrity. An attacker could exploit these
  to cause a denial of service. These issues only affected Ubuntu 12.10.
  (CVE-2012-5076, CVE-2012-5087, CVE-2012-5088)

  A denial of service vulnerability was found in OpenJDK. (CVE-2012-5081)

  Please see the references for more information.");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html");

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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b24-1.11.5-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b24-1.11.5-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b24-1.11.5-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b24-1.11.5-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b24-1.11.5-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
