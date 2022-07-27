###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for curl USN-3123-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842943");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-04 05:44:25 +0100 (Fri, 04 Nov 2016)");
  script_cve_id("CVE-2016-7141", "CVE-2016-7167", "CVE-2016-8615", "CVE-2016-8616",
		"CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620",
		"CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for curl USN-3123-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that curl incorrectly
  reused client certificates when built with NSS. A remote attacker could possibly
  use this issue to hijack the authentication of a TLS connection. (CVE-2016-7141)

Nguyen Vu Hoang discovered that curl incorrectly handled escaping certain
strings. A remote attacker could possibly use this issue to cause curl to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-7167)

It was discovered that curl incorrectly handled storing cookies. A remote
attacker could possibly use this issue to inject cookies for arbitrary
domains in the cookie jar. (CVE-2016-8615)

It was discovered that curl incorrect handled case when comparing user
names and passwords. A remote attacker with knowledge of a case-insensitive
version of the correct password could possibly use this issue to cause
a connection to be reused. (CVE-2016-8616)

It was discovered that curl incorrect handled memory when encoding to
base64. A remote attacker could possibly use this issue to cause curl to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-8617)

It was discovered that curl incorrect handled memory when preparing
formatted output. A remote attacker could possibly use this issue to cause
curl to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-8618)

It was discovered that curl incorrect handled memory when performing
Kerberos authentication. A remote attacker could possibly use this issue to
cause curl to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-8619)

Lu&#7853 t Nguy&#7877 n discovered that curl incorrectly handled parsing globs. A
remote attacker could possibly use this issue to cause curl to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2016-8620)

Lu&#7853 t Nguy&#7877 n discovered that curl incorrectly handled converting dates. A
remote attacker could possibly use this issue to cause curl to crash,
resulting in a denial of service. (CVE-2016-8621)

It was discovered that curl incorrectly handled URL percent-encoding
decoding. A remote attacker could possibly use this issue to cause curl to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-8622)

It was discovered that curl incorrectly handled shared cookies. A remote
server could possibly obtain incorrect cookies or other sensitive
information. (CVE-2016-8623)

Fernando Mu&#241 oz discovered that curl incorrect parsed certain URLs. A remote
attacker could possibly use this issue to trick curl into connecting to a
different host. (CVE-2016-8624)");
  script_tag(name:"affected", value:"curl on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 16.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3123-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|16\.04 LTS|16\.10)");

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

  if ((res = isdpkgvuln(pkg:"libcurl3:i386", ver:"7.35.0-1ubuntu2.10", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3:amd64", ver:"7.35.0-1ubuntu2.10", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:i386", ver:"7.35.0-1ubuntu2.10", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:amd64", ver:"7.35.0-1ubuntu2.10", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:i386", ver:"7.35.0-1ubuntu2.10", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:amd64", ver:"7.35.0-1ubuntu2.10", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libcurl3:i386", ver:"7.22.0-3ubuntu4.17", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3:amd64", ver:"7.22.0-3ubuntu4.17", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:i386", ver:"7.22.0-3ubuntu4.17", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:amd64", ver:"7.22.0-3ubuntu4.17", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:i386", ver:"7.22.0-3ubuntu4.17", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:amd64", ver:"7.22.0-3ubuntu4.17", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libcurl3:i386", ver:"7.47.0-1ubuntu2.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3:amd64", ver:"7.47.0-1ubuntu2.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:i386", ver:"7.47.0-1ubuntu2.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:amd64", ver:"7.47.0-1ubuntu2.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:i386", ver:"7.47.0-1ubuntu2.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:amd64", ver:"7.47.0-1ubuntu2.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.10")
{

  if ((res = isdpkgvuln(pkg:"libcurl3:i386", ver:"7.50.1-1ubuntu1.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3:amd64", ver:"7.50.1-1ubuntu1.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:i386", ver:"7.50.1-1ubuntu1.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:amd64", ver:"7.50.1-1ubuntu1.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:i386", ver:"7.50.1-1ubuntu1.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:amd64", ver:"7.50.1-1ubuntu1.1", rls:"UBUNTU16.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
