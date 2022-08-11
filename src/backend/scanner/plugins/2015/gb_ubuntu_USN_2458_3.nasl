###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-2458-3
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842079");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-01-28 06:11:29 +0100 (Wed, 28 Jan 2015)");
  script_cve_id("CVE-2014-8634", "CVE-2014-8635", "CVE-2014-8636", "CVE-2014-8637",
                "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8640", "CVE-2014-8641",
                "CVE-2014-8642");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for firefox USN-2458-3");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-2458-1 fixed vulnerabilities in Firefox.
This update introduced a regression which could make websites that use CSP fail to
load under some circumstances. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

Christian Holler, Patrick McManus, Christoph Diehl, Gary Kwong, Jesse
Ruderman, Byron Campen, Terrence Cole, and Nils Ohlmeier discovered
multiple memory safety issues in Firefox. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
these to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-8634, CVE-2014-8635)

Bobby Holley discovered that some DOM objects with certain properties
can bypass XrayWrappers in some circumstances. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to bypass security restrictions. (CVE-2014-8636)

Michal Zalewski discovered a use of uninitialized memory when rendering
malformed bitmap images on a canvas element. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to steal confidential information. (CVE-2014-8637)

Muneaki Nishimura discovered that requests from navigator.sendBeacon()
lack an origin header. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to conduct
cross-site request forgery (XSRF) attacks. (CVE-2014-8638)

Xiaofeng Zheng discovered that a web proxy returning a 407 response
could inject cookies in to the originally requested domain. If a user
connected to a malicious web proxy, an attacker could potentially exploit
this to conduct session-fixation attacks. (CVE-2014-8639)

Holger Fuhrmannek discovered a crash in Web Audio while manipulating
timelines. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service. (CVE-2014-8640)

Mitchell Harper discovered a use-after-free in WebRTC. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-8641)

Brian Smith discovered that OCSP responses would fail to verify if signed
by a delegated OCSP responder certificate with the id-pkix-ocsp-nocheck
extension, potentially allowing a user to connect to a site with a revoked
certificate. (CVE-2014-8642)");
  script_tag(name:"affected", value:"firefox on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2458-3/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.10|14\.04 LTS|12\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"35.0.1+build1-0ubuntu0.14.10.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"35.0.1+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"35.0.1+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
