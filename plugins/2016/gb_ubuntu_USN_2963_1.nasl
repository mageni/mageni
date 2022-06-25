###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openjdk-8 USN-2963-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842764");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-17 16:25:38 +0200 (Tue, 17 May 2016)");
  script_cve_id("CVE-2016-0686", "CVE-2016-0687", "CVE-2016-3427", "CVE-2016-0695",
                "CVE-2016-3426", "CVE-2016-3425");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for openjdk-8 USN-2963-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered
  in the OpenJDK JRE related to information disclosure, data integrity, and
  availability. An attacker could exploit these to cause a denial of service,
  expose sensitive data over the network, or possibly execute arbitrary code.
  (CVE-2016-0686, CVE-2016-0687, CVE-2016-3427)

  Multiple vulnerabilities were discovered in the OpenJDK JRE related
  to information disclosure. An attacker could exploit this to expose
  sensitive data over the network. (CVE-2016-0695, CVE-2016-3426)

  A vulnerability was discovered in the OpenJDK JRE related to availability.
  An attacker could exploit this to cause a denial of service.
  (CVE-2016-3425)");
  script_tag(name:"affected", value:"openjdk-8 on Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2963-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk:i386", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk:amd64", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk-headless:i386", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk-headless:amd64", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre:i386", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre:amd64", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-headless:i386", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-headless:amd64", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm:i386", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm:amd64", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-zero:i386", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-zero:amd64", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-source", ver:"8u91-b14-0ubuntu4~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
