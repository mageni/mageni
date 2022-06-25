###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3804_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for openjdk-lts USN-3804-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.843803");
  script_version("$Revision: 14288 $");
  script_cve_id("CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3150",
                "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3183", "CVE-2018-3214");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-11-01 06:05:33 +0100 (Thu, 01 Nov 2018)");
  script_name("Ubuntu Update for openjdk-lts USN-3804-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04 LTS|18\.10|16\.04 LTS)");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3804-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for
the 'openjdk-lts' package(s) announced via the USN-3804-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version
is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Security
component of OpenJDK did not properly ensure that manifest elements were signed
before use. An attacker could possibly use this to specially construct an
untrusted Java application or applet that could escape sandbox restrictions. (CVE-2018-3136)

Artem Smotrakov discovered that the HTTP client redirection handler
implementation in OpenJDK did not clear potentially sensitive information
in HTTP headers when following redirections to different hosts. An attacker
could use this to expose sensitive information. (CVE-2018-3139)

It was discovered that the Java Naming and Directory Interface (JNDI)
implementation in OpenJDK did not properly enforce restrictions specified
by system properties in some situations. An attacker could potentially use
this to execute arbitrary code. (CVE-2018-3149)

It was discovered that the Utility component of OpenJDK did not properly
ensure all attributes in a JAR were signed before use. An attacker could
use this to specially construct an untrusted Java application or applet
that could escape sandbox restrictions. This issue only affected Ubuntu
18.04 LTS and Ubuntu 18.10. (CVE-2018-3150)

It was discovered that the Hotspot component of OpenJDK did not properly
perform access checks in certain cases when performing field link
resolution. An attacker could use this to specially construct an untrusted
Java application or applet that could escape sandbox restrictions.
(CVE-2018-3169)

Felix Drre discovered that the Java Secure Socket Extension (JSSE)
implementation in OpenJDK did not ensure that the same endpoint
identification algorithm was used during TLS session resumption as during
initial session setup. An attacker could use this to expose sensitive
information. (CVE-2018-3180)

Krzysztof Szafraski discovered that the Scripting component did not
properly restrict access to the scripting engine in some situations. An
attacker could use this to specially construct an untrusted Java
application or applet that could escape sandbox restrictions.
(CVE-2018-3183)

Tobias Ospelt discovered that the Resource Interchange File Format (RIFF)
reader implementation in OpenJDK contained an infinite loop. An attacker
could use this to cause a denial of service. This issue only affected
Ubuntu 16.04 LTS. (CVE-2018-3214)");

  script_tag(name:"affected", value:"openjdk-lts on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"10.0.2+13-1ubuntu0.18.04.3", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"10.0.2+13-1ubuntu0.18.04.3", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"10.0.2+13-1ubuntu0.18.04.3", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.10")
{

  if ((res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.1+13-2ubuntu1", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.1+13-2ubuntu1", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.1+13-2ubuntu1", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u181-b13-1ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u181-b13-1ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u181-b13-1ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm", ver:"8u181-b13-1ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
