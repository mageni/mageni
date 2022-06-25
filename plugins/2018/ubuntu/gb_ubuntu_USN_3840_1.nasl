###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3840_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for openssl USN-3840-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843848");
  script_version("$Revision: 14288 $");
  script_cve_id("CVE-2018-0734", "CVE-2018-0735", "CVE-2018-5407");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-07 07:39:41 +0100 (Fri, 07 Dec 2018)");
  script_name("Ubuntu Update for openssl USN-3840-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|18\.04 LTS|18\.10|16\.04 LTS)");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3840-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the USN-3840-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Samuel Weiser discovered that OpenSSL incorrectly handled DSA signing. An
attacker could possibly use this issue to perform a timing side-channel
attack and recover private DSA keys. (CVE-2018-0734)

Samuel Weiser discovered that OpenSSL incorrectly handled ECDSA signing. An
attacker could possibly use this issue to perform a timing side-channel
attack and recover private ECDSA keys. This issue only affected Ubuntu
18.04 LTS and Ubuntu 18.10. (CVE-2018-0735)

Billy Bob Brumley, Cesar Pereida Garcia, Sohaib ul Hassan, Nicola Tuveri,
and Alejandro Cabrera Aldaya discovered that Simultaneous Multithreading
(SMT) architectures are vulnerable to side-channel leakage. This issue is
known as 'PortSmash'. An attacker could possibly use this issue to perform
a timing side-channel attack and recover private keys. (CVE-2018-5407)");

  script_tag(name:"affected", value:"openssl on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS.");

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

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu2.27", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2n-1ubuntu5.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.0g-2ubuntu4.3", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.10")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2n-1ubuntu6.1", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1-1ubuntu2.1", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2g-1ubuntu4.14", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
