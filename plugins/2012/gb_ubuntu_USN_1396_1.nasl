###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1396_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for eglibc USN-1396-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1396-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840929");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-03-12 12:42:00 +0530 (Mon, 12 Mar 2012)");
  script_cve_id("CVE-2009-5029", "CVE-2010-0015", "CVE-2011-1071", "CVE-2011-1659",
                "CVE-2011-1089", "CVE-2011-1095", "CVE-2011-1658", "CVE-2011-2702",
                "CVE-2011-4609", "CVE-2012-0864");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for eglibc USN-1396-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS|11\.04|8\.04 LTS)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1396-1");
  script_tag(name:"affected", value:"eglibc on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that the GNU C Library did not properly handle
  integer overflows in the timezone handling code. An attacker could use
  this to possibly execute arbitrary code by convincing an application
  to load a maliciously constructed tzfile. (CVE-2009-5029)

  It was discovered that the GNU C Library did not properly handle
  passwd.adjunct.byname map entries in the Network Information Service
  (NIS) code in the name service caching daemon (nscd). An attacker
  could use this to obtain the encrypted passwords of NIS accounts.
  This issue only affected Ubuntu 8.04 LTS. (CVE-2010-0015)

  Chris Evans reported that the GNU C Library did not properly
  calculate the amount of memory to allocate in the fnmatch() code. An
  attacker could use this to cause a denial of service or possibly
  execute arbitrary code via a maliciously crafted UTF-8 string.
  This issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu
  10.10. (CVE-2011-1071)

  Tomas Hoger reported that an additional integer overflow was possible
  in the GNU C Library fnmatch() code. An attacker could use this to
  cause a denial of service via a maliciously crafted UTF-8 string. This
  issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10
  and Ubuntu 11.04. (CVE-2011-1659)

  Dan Rosenberg discovered that the addmntent() function in the GNU C
  Library did not report an error status for failed attempts to write to
  the /etc/mtab file. This could allow an attacker to corrupt /etc/mtab,
  possibly causing a denial of service or otherwise manipulate mount
  options. This issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS,
  Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-1089)

  Harald van Dijk discovered that the locale program included with the
  GNU C library did not properly quote its output. This could allow a
  local attacker to possibly execute arbitrary code using a crafted
  localization string that was evaluated in a shell script. This
  issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu
  10.10. (CVE-2011-1095)

  It was discovered that the GNU C library loader expanded the
  $ORIGIN dynamic string token when RPATH is composed entirely of this
  token. This could allow an attacker to gain privilege via a setuid
  program that had this RPATH value. (CVE-2011-1658)

  It was discovered that the GNU C library implementation of memcpy
  optimized for Supplemental Streaming SIMD Extensions 3 (SSSE3)
  contained a possible integer overflow. An attacker could use this to
  cause a denial of service or possibly exec ...

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

  if ((res = isdpkgvuln(pkg:"libc-bin", ver:"2.12.1-0ubuntu10.4", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.12.1-0ubuntu10.4", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc-bin", ver:"2.11.1-0ubuntu7.10", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.11.1-0ubuntu7.10", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.13-0ubuntu13.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.7-10ubuntu8.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
