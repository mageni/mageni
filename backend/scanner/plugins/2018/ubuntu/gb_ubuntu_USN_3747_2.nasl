###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3747_2.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for openjdk-lts USN-3747-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843634");
  script_version("$Revision: 14288 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-13 07:20:12 +0200 (Thu, 13 Sep 2018)");
  script_cve_id("CVE-2018-2825", "CVE-2018-2826", "CVE-2018-2952", "CVE-2018-2972");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for openjdk-lts USN-3747-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-lts'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"USN-3747-1 fixed vulnerabilities in OpenJDK
10 for Ubuntu 18.04 LTS. Unfortunately, that update introduced a regression around
accessability support that prevented some Java applications from starting.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

It was discovered that OpenJDK did not properly validate types in some
situations. An attacker could use this to construct a Java class that could
possibly bypass sandbox restrictions. (CVE-2018-2825, CVE-2018-2826)

It was discovered that the PatternSyntaxException class in OpenJDK did not
properly validate arguments passed to it. An attacker could use this to
potentially construct a class that caused a denial of service (excessive
memory consumption). (CVE-2018-2952)

Daniel Bleichenbacher discovered a vulnerability in the Galois/Counter Mode
(GCM) mode of operation for symmetric block ciphers in OpenJDK. An attacker
could use this to expose sensitive information. (CVE-2018-2972)");
  script_tag(name:"affected", value:"openjdk-lts on Ubuntu 18.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3747-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"10.0.2+13-1ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-11-jdk-headless", ver:"10.0.2+13-1ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"10.0.2+13-1ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"10.0.2+13-1ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"10.0.2+13-1ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
