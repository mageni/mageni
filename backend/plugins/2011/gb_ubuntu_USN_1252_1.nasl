###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1252_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for tomcat6 USN-1252-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1252-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840803");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-11-11 09:59:15 +0530 (Fri, 11 Nov 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-1184", "CVE-2011-2204", "CVE-2011-2526", "CVE-2011-3190");
  script_name("Ubuntu Update for tomcat6 USN-1252-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1252-1");
  script_tag(name:"affected", value:"tomcat6 on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly implemented HTTP DIGEST
  authentication. An attacker could use this flaw to perform a variety of
  authentication attacks. (CVE-2011-1184)

  Polina Genova discovered that Tomcat incorrectly created log entries with
  passwords when encountering errors during JMX user creation. A local
  attacker could possibly use this flaw to obtain sensitive information. This
  issue only affected Ubuntu 10.04 LTS, 10.10 and 11.04. (CVE-2011-2204)

  It was discovered that Tomcat incorrectly validated certain request
  attributes when sendfile is enabled. A local attacker could bypass intended
  restrictions, or cause the JVM to crash, resulting in a denial of service.
  (CVE-2011-2526)

  It was discovered that Tomcat incorrectly handled certain AJP requests. A
  remote attacker could use this flaw to spoof requests, bypass
  authentication, and obtain sensitive information. This issue only affected
  Ubuntu 10.04 LTS, 10.10 and 11.04. (CVE-2011-3190)");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.28-2ubuntu1.5", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.24-2ubuntu1.9", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.28-10ubuntu2.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
