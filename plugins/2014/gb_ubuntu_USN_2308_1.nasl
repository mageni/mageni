###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2308_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for openssl USN-2308-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841924");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-08-08 06:02:31 +0200 (Fri, 08 Aug 2014)");
  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508",
                "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511", "CVE-2014-3512",
                "CVE-2014-5139");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for openssl USN-2308-1");

  script_tag(name:"affected", value:"openssl on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS");
  script_tag(name:"insight", value:"Adam Langley and Wan-Teh Chang discovered that OpenSSL
incorrectly handled certain DTLS packets. A remote attacker could use this issue
to cause OpenSSL to crash, resulting in a denial of service. (CVE-2014-3505)

Adam Langley discovered that OpenSSL incorrectly handled memory when
processing DTLS handshake messages. A remote attacker could use this issue
to cause OpenSSL to consume memory, resulting in a denial of service.
(CVE-2014-3506)

Adam Langley discovered that OpenSSL incorrectly handled memory when
processing DTLS fragments. A remote attacker could use this issue to cause
OpenSSL to leak memory, resulting in a denial of service. This issue
only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3507)

Ivan Fratric discovered that OpenSSL incorrectly leaked information in
the pretty printing functions. When OpenSSL is used with certain
applications, an attacker may use this issue to possibly gain access to
sensitive information. (CVE-2014-3508)

Gabor Tyukasz discovered that OpenSSL contained a race condition when
processing serverhello messages. A malicious server could use this issue
to cause clients to crash, resulting in a denial of service. This issue
only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3509)

Felix Gr&#246 bert discovered that OpenSSL incorrectly handled certain DTLS
handshake messages. A malicious server could use this issue to cause
clients to crash, resulting in a denial of service. (CVE-2014-3510)

David Benjamin and Adam Langley discovered that OpenSSL incorrectly
handled fragmented ClientHello messages. If a remote attacker were able to
perform a man-in-the-middle attack, this flaw could be used to force a
protocol downgrade to TLS 1.0. This issue only affected Ubuntu 12.04 LTS
and Ubuntu 14.04 LTS. (CVE-2014-3511)

Sean Devlin and Watson Ladd discovered that OpenSSL incorrectly handled
certain SRP parameters. A remote attacker could use this with applications
that use SRP to cause a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-3512)

Joonas Kuorilehto and Riku Hietam&#228 ki discovered that OpenSSL incorrectly
handled certain Server Hello messages that specify an SRP ciphersuite. A
malicious server could use this issue to cause clients to crash, resulting
in a denial of service. This issue only affected Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2014-5139)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2308-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|10\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1f-1ubuntu2.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.17", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8k-7ubuntu8.20", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
