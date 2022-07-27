###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2302_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for tomcat7 USN-2302-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841921");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-08-05 16:51:08 +0530 (Tue, 05 Aug 2014)");
  script_cve_id("CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Ubuntu Update for tomcat7 USN-2302-1");

  script_tag(name:"affected", value:"tomcat7 on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS");
  script_tag(name:"insight", value:"David Jorm discovered that Tomcat incorrectly handled certain
requests submitted using chunked transfer encoding. A remote attacker could use
this flaw to cause the Tomcat server to consume resources, resulting in a denial
of service. (CVE-2014-0075)

It was discovered that Tomcat did not properly restrict XSLT stylesheets.
An attacker could use this issue with a crafted web application to bypass
security-manager restrictions and read arbitrary files. (CVE-2014-0096)

It was discovered that Tomcat incorrectly handled certain Content-Length
headers. A remote attacker could use this flaw in configurations where
Tomcat is behind a reverse proxy to perform HTTP request smuggling attacks.
(CVE-2014-0099)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2302-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat7'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|10\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.52-1ubuntu0.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.35-1ubuntu3.5", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.24-2ubuntu1.16", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
