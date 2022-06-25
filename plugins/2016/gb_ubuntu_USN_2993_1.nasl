###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-2993-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842785");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-06-10 05:23:29 +0200 (Fri, 10 Jun 2016)");
  script_cve_id("CVE-2016-2815", "CVE-2016-2818", "CVE-2016-2819", "CVE-2016-2821", "CVE-2016-2822", "CVE-2016-2825", "CVE-2016-2828", "CVE-2016-2829", "CVE-2016-2831", "CVE-2016-2832", "CVE-2016-2833", "CVE-2016-2834");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for firefox USN-2993-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Christian Holler, Gary Kwong, Jesse Ruderman, Tyson Smith, Timothy Nikkel,
Sylvestre Ledru, Julian Seward, Olli Pettay, Karl Tomlinson, Christoph
Diehl, Julian Hector, Jan de Mooij, Mats Palmgren, and Tooru Fujisawa
discovered multiple memory safety issues in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-2815, CVE-2016-2818)

A buffer overflow was discovered when parsing HTML5 fragments in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-2819)

A use-after-free was discovered in contenteditable mode in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-2821)

Jordi Chancel discovered a way to use a persistent menu within a  select
element and place this in an arbitrary location. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to spoof the addressbar contents. (CVE-2016-2822)

Armin Razmdjou that the location.host property can be set to an arbitrary
string after creating an invalid data: URI. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to bypass some same-origin protections. (CVE-2016-2825)

A use-after-free was discovered when processing WebGL content in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-2828)

Tim McCormack discovered that the permissions notification can show the
wrong icon when a page requests several permissions in quick succession.
An attacker could potentially exploit this by tricking the user in to
giving consent for access to the wrong resource. (CVE-2016-2829)

It was discovered that a pointerlock can be created in a fullscreen
window without user consent in some circumstances, and this pointerlock
cannot be cancelled without quitting Firefox. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service or conduct clickjacking attacks.
(CVE-2016-2831)

 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"firefox on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2993-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|16\.04 LTS|15\.10)");

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"47.0+build3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"47.0+build3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"47.0+build3-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"47.0+build3-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}