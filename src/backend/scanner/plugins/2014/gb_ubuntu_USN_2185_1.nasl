###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2185_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for firefox USN-2185-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841802");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-05-05 11:25:24 +0530 (Mon, 05 May 2014)");
  script_cve_id("CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1522", "CVE-2014-1523",
                "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1528", "CVE-2014-1529",
                "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1492", "CVE-2014-1532",
                "CVE-2014-1526");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-2185-1");

  script_tag(name:"affected", value:"firefox on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Bobby Holley, Carsten Book, Christoph Diehl, Gary Kwong,
Jan de Mooij, Jesse Ruderman, Nathan Froyd, John Schoenick, Karl Tomlinson,
Vladimir Vukicevic and Christian Holler discovered multiple memory safety
issues in Firefox. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of
service via application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2014-1518, CVE-2014-1519)

An out of bounds read was discovered in Web Audio. An attacker could
potentially exploit this cause a denial of service via application crash
or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-1522)

Abhishek Arya discovered an out of bounds read when decoding JPG images.
An attacker could potentially exploit this to cause a denial of service
via application crash. (CVE-2014-1523)

Abhishek Arya discovered a buffer overflow when a script uses a non-XBL
object as an XBL object. An attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1524)

Abhishek Arya discovered a use-after-free in the Text Track Manager when
processing HTML video. An attacker could potentially exploit this to cause
a denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2014-1525)

Jukka Jyl&#228 nki discovered an out-of-bounds write in Cairo when working
with canvas in some circumstances. An attacker could potentially exploit
this to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1528)

Mariusz Mlynski discovered that sites with notification permissions can
run script in a privileged context in some circumstances. An attacker
could exploit this to execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2014-1529)

It was discovered that browser history navigations could be used to load
a site with the addressbar displaying the wrong address. An attacker could
potentially exploit this to conduct cross-site scripting or phishing
attacks. (CVE-2014-1530)

A use-after-free was discovered when resizing images in some
circumstances. An attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2014-1531)

Christian Heimes discovered that NSS did not handle IDNA domain prefixes
correctly for wild ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2185-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|13\.10|12\.10)");

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"29.0+build1-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"29.0+build1-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"29.0+build1-0ubuntu0.13.10.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"29.0+build1-0ubuntu0.12.10.3", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
