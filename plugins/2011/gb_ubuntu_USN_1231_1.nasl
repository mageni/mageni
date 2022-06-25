###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1231_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for php5 USN-1231-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1231-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840782");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-1938", "CVE-2011-2202", "CVE-2011-2483", "CVE-2011-3182",
                "CVE-2011-3267", "CVE-2011-1657", "CVE-2010-1914", "CVE-2010-2484");
  script_name("Ubuntu Update for php5 USN-1231-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS|11\.04|8\.04 LTS)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1231-1");
  script_tag(name:"affected", value:"php5 on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mateusz Kocielski, Marek Kroemeke and Filip Palian discovered that a
  stack-based buffer overflow existed in the socket_connect function's
  handling of long pathnames for AF_UNIX sockets. A remote attacker
  might be able to exploit this to execute arbitrary code. However,
  the default compiler options for affected releases should reduce
  the vulnerability to a denial of service. This issue affected Ubuntu
  10.04 LTS, Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-1938)

  Krzysztof Kotowicz discovered that the PHP post handler function
  does not properly restrict filenames in multipart/form-data POST
  requests. This may allow remote attackers to conduct absolute
  path traversal attacks and possibly create or overwrite arbitrary
  files. This issue affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu
  10.10 and Ubuntu 11.04. (CVE-2011-2202)

  It was discovered that the crypt function for blowfish does not
  properly handle 8-bit characters. This could make it easier for an
  attacker to discover a cleartext password containing an 8-bit character
  that has a matching blowfish crypt value. This issue affected Ubuntu
  10.04 LTS, Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-2483)

  It was discovered that PHP did not properly check the return values of
  the malloc(3), calloc(3) and realloc(3) library functions in multiple
  locations. This could allow an attacker to cause a denial of service
  via a NULL pointer dereference or possibly execute arbitrary code.
  This issue affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10
  and Ubuntu 11.04. (CVE-2011-3182)

  Maksymilian Arciemowicz discovered that PHP did not properly implement
  the error_log function. This could allow an attacker to cause a denial
  of service via an application crash. This issue affected Ubuntu 10.04
  LTS, Ubuntu 10.10, Ubuntu 11.04 and Ubuntu 11.10. (CVE-2011-3267)

  Maksymilian Arciemowicz discovered that the ZipArchive functions
  addGlob() and addPattern() did not properly check their flag arguments.
  This could allow a malicious script author to cause a denial of
  service via application crash. This issue affected Ubuntu 10.04 LTS,
  Ubuntu 10.10, Ubuntu 11.04 and Ubuntu 11.10. (CVE-2011-1657)

  It was discovered that the Xend opcode parser in PHP could be interrupted
  while handling the shift-left, shift-right, and bitwise-xor opcodes.
  This could allow a malicious script author to expose memory
  contents. This issue affected Ubuntu 10.04 LTS. (CVE-2010-1914)

  It was discovered that the strrchr function in PHP could be interrupted
  by a malicious script, allowing the exposure of memory contents. This
  issue affected Ubuntu 8.04 LTS. (CVE-2010-2484)");
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

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.3-1ubuntu9.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.3-1ubuntu9.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.3-1ubuntu9.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.3.3-1ubuntu9.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.2-1ubuntu4.10", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.2-1ubuntu4.10", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.2-1ubuntu4.10", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.3.2-1ubuntu4.10", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.5-1ubuntu7.3", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.5-1ubuntu7.3", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.5-1ubuntu7.3", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.3.5-1ubuntu7.3", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.4-2ubuntu5.18", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.4-2ubuntu5.18", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.4-2ubuntu5.18", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.2.4-2ubuntu5.18", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
