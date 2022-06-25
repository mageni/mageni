###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3473_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for openjdk-8 USN-3473-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843361");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-11-09 07:28:02 +0100 (Thu, 09 Nov 2017)");
  script_cve_id("CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295",
                "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348",
                "CVE-2017-10357", "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355",
                "CVE-2017-10356", "CVE-2017-10388");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for openjdk-8 USN-3473-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that the Smart Card IO
  subsystem in OpenJDK did not properly maintain state. An attacker could use this
  to specially construct an untrusted Java application or applet to gain access to
  a smart card, bypassing sandbox restrictions. (CVE-2017-10274) Gaston Traberg
  discovered that the Serialization component of OpenJDK did not properly limit
  the amount of memory allocated when performing deserializations. An attacker
  could use this to cause a denial of service (memory exhaustion).
  (CVE-2017-10281) It was discovered that the Remote Method Invocation (RMI)
  component in OpenJDK did not properly handle unreferenced objects. An attacker
  could use this to specially construct an untrusted Java application or applet
  that could escape sandbox restrictions. (CVE-2017-10285) It was discovered that
  the HTTPUrlConnection classes in OpenJDK did not properly handle newlines. An
  attacker could use this to convince a Java application or applet to inject
  headers into http requests. (CVE-2017-10295) Francesco Palmarini, Marco
  Squarcina, Mauro Tempesta, and Riccardo Focardi discovered that the
  Serialization component of OpenJDK did not properly restrict the amount of
  memory allocated when deserializing objects from Java Cryptography Extension
  KeyStore (JCEKS). An attacker could use this to cause a denial of service
  (memory exhaustion). (CVE-2017-10345) It was discovered that the Hotspot
  component of OpenJDK did not properly perform loader checks when handling the
  invokespecial JVM instruction. An attacker could use this to specially construct
  an untrusted Java application or applet that could escape sandbox restrictions.
  (CVE-2017-10346) Gaston Traberg discovered that the Serialization component of
  OpenJDK did not properly limit the amount of memory allocated when performing
  deserializations in the SimpleTimeZone class. An attacker could use this to
  cause a denial of service (memory exhaustion). (CVE-2017-10347) It was
  discovered that the Serialization component of OpenJDK did not properly limit
  the amount of memory allocated when performing deserializations. An attacker
  could use this to cause a denial of service (memory exhaustion).
  (CVE-2017-10348, CVE-2017-10357) It was discovered that the JAXP component in
  OpenJDK did not properly limit the amount of memory allocated when performing
  deserializations. An attacker could use this to cause a denial of service
  (memory exhaustion). (CVE-2017-10349) It was discovered that the JAX-WS
  component in OpenJDK did not properly limit the amount of memory allocated when
  performing deserializations. An attacker ... Description truncated, for more
  information please check the Reference URL");
  script_tag(name:"affected", value:"openjdk-8 on Ubuntu 17.10,
  Ubuntu 17.04,
  Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3473-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(17\.10|17\.04|16\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk:amd64", ver:"8u151-b12-0ubuntu0.17.10.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk:i386", ver:"8u151-b12-0ubuntu0.17.10.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk-headless:amd64", ver:"8u151-b12-0ubuntu0.17.10.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk-headless:i386", ver:"8u151-b12-0ubuntu0.17.10.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre:amd64", ver:"8u151-b12-0ubuntu0.17.10.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre:i386", ver:"8u151-b12-0ubuntu0.17.10.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-headless:amd64", ver:"8u151-b12-0ubuntu0.17.10.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-headless:i386", ver:"8u151-b12-0ubuntu0.17.10.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-zero:amd64", ver:"8u151-b12-0ubuntu0.17.10.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-zero:i386", ver:"8u151-b12-0ubuntu0.17.10.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk:amd64", ver:"8u151-b12-0ubuntu0.17.04.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk:i386", ver:"8u151-b12-0ubuntu0.17.04.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk-headless:amd64", ver:"8u151-b12-0ubuntu0.17.04.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk-headless:i386", ver:"8u151-b12-0ubuntu0.17.04.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre:amd64", ver:"8u151-b12-0ubuntu0.17.04.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre:i386", ver:"8u151-b12-0ubuntu0.17.04.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-headless:amd64", ver:"8u151-b12-0ubuntu0.17.04.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

 if ((res = isdpkgvuln(pkg:"openjdk-8-jre-headless:i386", ver:"8u151-b12-0ubuntu0.17.04.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-zero:amd64", ver:"8u151-b12-0ubuntu0.17.04.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-zero:i386", ver:"8u151-b12-0ubuntu0.17.04.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk:amd64", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk:i386", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk-headless:amd64", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk-headless:i386", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre:amd64", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre:i386", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-headless:amd64", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-headless:i386", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm:amd64", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm:i386", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-zero:amd64", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-zero:i386", ver:"8u151-b12-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
