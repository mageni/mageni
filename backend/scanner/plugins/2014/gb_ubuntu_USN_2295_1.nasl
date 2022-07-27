###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2295_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for firefox USN-2295-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841914");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-07-28 16:40:56 +0530 (Mon, 28 Jul 2014)");
  script_cve_id("CVE-2014-1547", "CVE-2014-1548", "CVE-2014-1549", "CVE-2014-1550",
                "CVE-2014-1561", "CVE-2014-1555", "CVE-2014-1556", "CVE-2014-1544",
                "CVE-2014-1557", "CVE-2014-1558", "CVE-2014-1559", "CVE-2014-1560",
                "CVE-2014-1552");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-2295-1");

  script_tag(name:"affected", value:"firefox on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Christian Holler, David Keeler, Byron Campen, Gary Kwong,
Jesse Ruderman, Andrew McCreight, Alon Zakai, Bobby Holley, Jonathan Watt,
Shu-yu Guo, Steve Fink, Terrence Cole, Gijs Kruitbosch and C&#259 t&#259 lin
Badea discovered multiple memory safety issues in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could potentially
exploit these to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1547, CVE-2014-1548)

Atte Kettunen discovered a buffer overflow when interacting with WebAudio
buffers. An attacker could potentially exploit this to cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2014-1549)

Atte Kettunen discovered a use-after-free in WebAudio. An attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-1550)

David Chan and Gijs Kruitbosch discovered that web content could spoof
UI customization events in some circumstances, resulting in a limited
ability to move UI icons. (CVE-2014-1561)

Jethro Beekman discovered a use-after-free when the FireOnStateChange
event is triggered in some circumstances. An attacker could potentially
exploit this to cause a denial of service via application crash or
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1555)

Patrick Cozzi discovered a crash when using the Cesium JS library to
generate WebGL content. An attacker could potentially exploit this to
execute arbitrary code with the privilges of the user invoking Firefox.
(CVE-2014-1556)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in
CERT_DestroyCertificate. An attacker could potentially exploit this to
cause a denial of service via application crash or execute arbitrary
code with the privileges of the user invoking Firefox. (CVE-2014-1544)

A crash was discovered in Skia when scaling an image, if the scaling
operation takes too long. An attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1557)

Christian Holler discovered several issues when parsing certificates
with non-standard character encoding, resulting in the inability to
use valid SSL certificates in some circumstances. (CVE-2014-1558,
CVE-2014-1559, CVE-2014-1560)

Boris Zbarsky discovered that network redirects could cause an iframe
to escape the confinements defined by its sandbox attribute in
some circumstances. An attacker could potentially exploit this to
conduct cross-site scripting attacks. (CVE-2014-1552)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2295-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"31.0+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"31.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
