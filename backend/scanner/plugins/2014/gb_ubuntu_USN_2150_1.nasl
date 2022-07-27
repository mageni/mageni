###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2150_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for firefox USN-2150-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841757");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-03-20 09:49:40 +0530 (Thu, 20 Mar 2014)");
  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1497", "CVE-2014-1498",
                "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502", "CVE-2014-1504",
                "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510",
                "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514",
                "CVE-2014-1508");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-2150-1");

  script_tag(name:"affected", value:"firefox on Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Benoit Jacob, Olli Pettay, Jan Varga, Jan de Mooij, Jesse
Ruderman, Dan Gohman, Christoph Diehl, Gregor Wagner, Gary Kwong, Luke Wagner,
Rob Fletcher and Makoto Kato discovered multiple memory safety issues in
Firefox. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2014-1493, CVE-2014-1494)

Atte Kettunen discovered an out-of-bounds read during WAV file decoding.
An attacker could potentially exploit this to cause a denial of service
via application crash. (CVE-2014-1497)

David Keeler discovered that crypto.generateCRFMRequest did not correctly
validate all arguments. An attacker could potentially exploit this to
cause a denial of service via application crash. (CVE-2014-1498)

Ehsan Akhgari discovered that the WebRTC permission dialog can display
the wrong originating site information under some circumstances. An
attacker could potentially exploit this by tricking a user in order to
gain access to their webcam or microphone. (CVE-2014-1499)

Tim Philipp Schaefers and Sebastian Neef discovered that onbeforeunload
events used with page navigations could make the browser unresponsive
in some circumstances. An attacker could potentially exploit this to
cause a denial of service. (CVE-2014-1500)

Jeff Gilbert discovered that WebGL content could manipulate content from
another sites WebGL context. An attacker could potentially exploit this
to conduct spoofing attacks. (CVE-2014-1502)

Nicolas Golubovic discovered that CSP could be bypassed for data:
documents during session restore. An attacker could potentially exploit
this to conduct cross-site scripting attacks. (CVE-2014-1504)

Robert O'Callahan discovered a mechanism for timing attacks involving
SVG filters and displacements input to feDisplacementMap. An attacker
could potentially exploit this to steal confidential information across
domains. (CVE-2014-1505)

Tyson Smith and Jesse Schwartzentruber discovered an out-of-bounds read
during polygon rendering in MathML. An attacker could potentially exploit
this to steal confidential information across domains. (CVE-2014-1508)

John Thomson discovered a memory corruption bug in the Cairo graphics
library. If a user had a malicious extension installed, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-1509)

Mariusz Mlynski discovered ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2150-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|13\.10|12\.10)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"28.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"28.0+build2-0ubuntu0.13.10.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"28.0+build2-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
