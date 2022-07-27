###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1806_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for openjdk-7 USN-1806-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841405");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-04-25 10:46:38 +0530 (Thu, 25 Apr 2013)");
  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537",
                "CVE-2013-1557", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384",
                "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2426",
                "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431", "CVE-2013-2436",
                "CVE-2013-2415", "CVE-2013-2424", "CVE-2013-2417", "CVE-2013-2419",
                "CVE-2013-2423", "CVE-2013-1558");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for openjdk-7 USN-1806-1");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1806-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.10");
  script_tag(name:"affected", value:"openjdk-7 on Ubuntu 12.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Ben Murphy discovered a vulnerability in the OpenJDK JRE related to
  information disclosure and data integrity. An attacker could exploit this
  to execute arbitrary code. (CVE-2013-0401)

  James Forshaw discovered a vulnerability in the OpenJDK JRE related to
  information disclosure, data integrity and availability. An attacker could
  exploit this to execute arbitrary code. (CVE-2013-1488)

  Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure, data integrity and availability. An attacker could
  exploit these to cause a denial of service or expose sensitive data over
  the network. (CVE-2013-1518, CVE-2013-1537, CVE-2013-1557, CVE-2013-1569,
  CVE-2013-2383, CVE-2013-2384, CVE-2013-2420, CVE-2013-2421, CVE-2013-2422,
  CVE-2013-2426, CVE-2013-2429, CVE-2013-2430, CVE-2013-2431, CVE-2013-2436)

  Two vulnerabilities were discovered in the OpenJDK JRE related to
  confidentiality. An attacker could exploit these to expose sensitive data
  over the network. (CVE-2013-2415, CVE-2013-2424)

  Two vulnerabilities were discovered in the OpenJDK JRE related to
  availability. An attacker could exploit these to cause a denial of service.
  (CVE-2013-2417, CVE-2013-2419)

  A vulnerability was discovered in the OpenJDK JRE related to data
  integrity. (CVE-2013-2423)");
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

if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u21-2.3.9-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u21-2.3.9-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u21-2.3.9-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u21-2.3.9-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u21-2.3.9-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
