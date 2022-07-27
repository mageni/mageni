###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openssl USN-2959-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842729");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-04 05:19:55 +0200 (Wed, 04 May 2016)");
  script_cve_id("CVE-2016-2108", "CVE-2016-2107", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2109");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for openssl USN-2959-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Huzaifa Sidhpurwala, Hanno B&#246 ck, and
  David Benjamin discovered that OpenSSL incorrectly handled memory when decoding
  ASN.1 structures. A remote attacker could use this issue to cause OpenSSL to
  crash, resulting in a denial of service, or possibly execute arbitrary code.
  (CVE-2016-2108)

  Juraj Somorovsky discovered that OpenSSL incorrectly performed padding when
  the connection uses the AES CBC cipher and the server supports AES-NI. A
  remote attacker could possibly use this issue to perform a padding oracle
  attack and decrypt traffic. (CVE-2016-2107)

  Guido Vranken discovered that OpenSSL incorrectly handled large amounts of
  input data to the EVP_EncodeUpdate() function. A remote attacker could use
  this issue to cause OpenSSL to crash, resulting in a denial of service, or
  possibly execute arbitrary code. (CVE-2016-2105)

  Guido Vranken discovered that OpenSSL incorrectly handled large amounts of
  input data to the EVP_EncryptUpdate() function. A remote attacker could use
  this issue to cause OpenSSL to crash, resulting in a denial of service, or
  possibly execute arbitrary code. (CVE-2016-2106)

  Brian Carpenter discovered that OpenSSL incorrectly handled memory when
  ASN.1 data is read from a BIO. A remote attacker could possibly use this
  issue to cause memory consumption, resulting in a denial of service.
  (CVE-2016-2109)

  As a security improvement, this update also modifies OpenSSL behaviour to
  reject DH key sizes below 1024 bits, preventing a possible downgrade
  attack.");
  script_tag(name:"affected", value:"openssl on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2959-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|15\.10)");

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

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1f-1ubuntu2.19", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:amd64", ver:"1.0.1f-1ubuntu2.19", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1-4ubuntu5.36", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:amd64", ver:"1.0.1-4ubuntu5.36", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.2d-0ubuntu1.5", rls:"UBUNTU15.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:amd64", ver:"1.0.2d-0ubuntu1.5", rls:"UBUNTU15.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}