###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3824_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for openjdk-7 USN-3824-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843826");
  script_version("$Revision: 14288 $");
  script_cve_id("CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3169", "CVE-2018-3180");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-11-16 06:00:09 +0100 (Fri, 16 Nov 2018)");
  script_name("Ubuntu Update for openjdk-7 USN-3824-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04 LTS");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3824-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7'
  package(s) announced via the USN-3824-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Security component of OpenJDK did not properly
ensure that manifest elements were signed before use. An attacker could
possibly use this to specially construct an untrusted Java application or
applet that could escape sandbox restrictions. (CVE-2018-3136)

Artem Smotrakov discovered that the HTTP client redirection handler
implementation in OpenJDK did not clear potentially sensitive information
in HTTP headers when following redirections to different hosts. An attacker
could use this to expose sensitive information. (CVE-2018-3139)

It was discovered that the Java Naming and Directory Interface (JNDI)
implementation in OpenJDK did not properly enforce restrictions specified
by system properties in some situations. An attacker could potentially use
this to execute arbitrary code. (CVE-2018-3149)

It was discovered that the Hotspot component of OpenJDK did not properly
perform access checks in certain cases when performing field link
resolution. An attacker could use this to specially construct an untrusted
Java application or applet that could escape sandbox restrictions.
(CVE-2018-3169)

Felix Dörre discovered that the Java Secure Socket Extension (JSSE)
implementation in OpenJDK did not ensure that the same endpoint
identification algorithm was used during TLS session resumption as during
initial session setup. An attacker could use this to expose sensitive
information. (CVE-2018-3180)");

  script_tag(name:"affected", value:"openjdk-7 on Ubuntu 14.04 LTS.");

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

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u181-2.6.14-0ubuntu0.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jdk", ver:"7u181-2.6.14-0ubuntu0.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u181-2.6.14-0ubuntu0.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u181-2.6.14-0ubuntu0.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u181-2.6.14-0ubuntu0.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
