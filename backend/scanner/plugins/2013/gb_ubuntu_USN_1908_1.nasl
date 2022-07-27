###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1908_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for openjdk-6 USN-1908-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841510");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-08-08 11:38:20 +0530 (Thu, 08 Aug 2013)");
  script_cve_id("CVE-2013-1500", "CVE-2013-2454", "CVE-2013-2458", "CVE-2013-1571",
                "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2443", "CVE-2013-2446",
                "CVE-2013-2447", "CVE-2013-2449", "CVE-2013-2452", "CVE-2013-2456",
                "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2450", "CVE-2013-2448",
                "CVE-2013-2451", "CVE-2013-2459", "CVE-2013-2461", "CVE-2013-2463",
                "CVE-2013-2465", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471",
                "CVE-2013-2472", "CVE-2013-2473", "CVE-2013-3743", "CVE-2013-2453",
                "CVE-2013-2455", "CVE-2013-2457");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for openjdk-6 USN-1908-1");

  script_tag(name:"affected", value:"openjdk-6 on Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit these
to expose sensitive data over the network. (CVE-2013-1500, CVE-2013-2454,
CVE-2013-2458)

A vulnerability was discovered in the OpenJDK Javadoc related to data
integrity. (CVE-2013-1571)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure and availability. An attacker could exploit this to cause a
denial of service or expose sensitive data over the network.
(CVE-2013-2407)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose sensitive
data over the network. (CVE-2013-2412, CVE-2013-2443, CVE-2013-2446,
CVE-2013-2447, CVE-2013-2449, CVE-2013-2452, CVE-2013-2456)

Several vulnerabilities were discovered in the OpenJDK JRE related to
availability. An attacker could exploit these to cause a denial of service.
(CVE-2013-2444, CVE-2013-2445, CVE-2013-2450)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity and availability. An attacker could
exploit these to cause a denial of service or expose sensitive data over
the network. (CVE-2013-2448, CVE-2013-2451, CVE-2013-2459, CVE-2013-2461,
CVE-2013-2463, CVE-2013-2465, CVE-2013-2469, CVE-2013-2470, CVE-2013-2471,
CVE-2013-2472, CVE-2013-2473, CVE-2013-3743)

Several vulnerabilities were discovered in the OpenJDK JRE related to data
integrity. (CVE-2013-2453, CVE-2013-2455, CVE-2013-2457)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1908-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|10\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.6-1ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b27-1.12.6-1ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b27-1.12.6-1ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.6-1ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.6-1ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.6-1ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.6-1ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.6-1ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b27-1.12.6-1ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.6-1ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.6-1ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.6-1ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.6-1ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
