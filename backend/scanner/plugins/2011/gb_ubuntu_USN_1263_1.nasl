###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1263_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for icedtea-web USN-1263-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1263-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840805");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-11-18 09:46:15 +0530 (Fri, 18 Nov 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3377", "CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544",
                "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552",
                "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3556", "CVE-2011-3557",
                "CVE-2011-3558", "CVE-2011-3560");
  script_name("Ubuntu Update for icedtea-web USN-1263-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1263-1");
  script_tag(name:"affected", value:"icedtea-web on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Deepak Bhole discovered a flaw in the Same Origin Policy (SOP)
  implementation in the IcedTea web browser plugin. This could allow a
  remote attacker to open connections to certain hosts that should
  not be permitted. (CVE-2011-3377)

  Juliano Rizzo and Thai Duong discovered that the block-wise AES
  encryption algorithm block-wise as used in TLS/SSL was vulnerable to
  a chosen-plaintext attack. This could allow a remote attacker to view
  confidential data. (CVE-2011-3389)

  It was discovered that a type confusion flaw existed in the in
  the Internet Inter-Orb Protocol (IIOP) deserialization code. A
  remote attacker could use this to cause an untrusted application
  or applet to execute arbitrary code by deserializing malicious
  input. (CVE-2011-3521)

  It was discovered that the Java scripting engine did not perform
  SecurityManager checks. This could allow a remote attacker to cause
  an untrusted application or applet to execute arbitrary code with
  the full privileges of the JVM. (CVE-2011-3544)

  It was discovered that the InputStream class used a global buffer to
  store input bytes skipped. An attacker could possibly use this to gain
  access to sensitive information. (CVE-2011-3547)

  It was discovered that a vulnerability existed in the AWTKeyStroke
  class. A remote attacker could cause an untrusted application or applet
  to execute arbitrary code. (CVE-2011-3548)

  It was discovered that an integer overflow vulnerability existed
  in the TransformHelper class in the Java2D implementation. A remote
  attacker could use this cause a denial of service via an application
  or applet crash or possibly execute arbitrary code. (CVE-2011-3551)

  It was discovered that the default number of available UDP sockets for
  applications running under SecurityManager restrictions was set too
  high. A remote attacker could use this with a malicious application or
  applet exhaust the number of available UDP sockets to cause a denial
  of service for other applets or applications running within the same
  JVM. (CVE-2011-3552)

  It was discovered that Java API for XML Web Services (JAX-WS) could
  incorrectly expose a stack trace. A remote attacker could potentially
  use this to gain access to sensitive information. (CVE-2011-3553)

  It was discovered that the unpacker for pack200 JAR files did not
  sufficiently check for errors. An attacker could cause a denial of
  service or possibly execute arbitrary code through a specially crafted
  pack200 JAR file. (CVE-2011-3554)

  It was discovered that the RMI registratio ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.1.1-0ubuntu1~11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-plugin", ver:"1.1.1-0ubuntu1~11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
