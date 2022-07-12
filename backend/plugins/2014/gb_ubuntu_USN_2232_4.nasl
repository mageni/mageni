###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2232_4.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for openssl USN-2232-4
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841933");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-08-19 05:58:49 +0200 (Tue, 19 Aug 2014)");
  script_cve_id("CVE-2014-0195", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for openssl USN-2232-4");

  script_tag(name:"affected", value:"openssl on Ubuntu 10.04 LTS");
  script_tag(name:"insight", value:"USN-2232-1 fixed vulnerabilities in OpenSSL. One of the patch
backports for Ubuntu 10.04 LTS caused a regression for certain applications.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

J&#252 ri Aedla discovered that OpenSSL incorrectly handled invalid DTLS
fragments. A remote attacker could use this issue to cause OpenSSL to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS, Ubuntu 13.10, and
Ubuntu 14.04 LTS. (CVE-2014-0195)
Imre Rad discovered that OpenSSL incorrectly handled DTLS recursions. A
remote attacker could use this issue to cause OpenSSL to crash, resulting
in a denial of service. (CVE-2014-0221)
KIKUCHI Masashi discovered that OpenSSL incorrectly handled certain
handshakes. A remote attacker could use this flaw to perform a
man-in-the-middle attack and possibly decrypt and modify traffic.
(CVE-2014-0224)
Felix Gr&#246 bert and Ivan Fratri&#263  discovered that OpenSSL incorrectly
handled anonymous ECDH ciphersuites. A remote attacker could use this issue to
cause OpenSSL to crash, resulting in a denial of service. This issue only
affected Ubuntu 12.04 LTS, Ubuntu 13.10, and Ubuntu 14.04 LTS.
(CVE-2014-3470)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2232-4/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8k-7ubuntu8.21", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
