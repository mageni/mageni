###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-3112-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842931");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-08 15:52:48 +0530 (Tue, 08 Nov 2016)");
  script_cve_id("CVE-2016-5250", "CVE-2016-5257", "CVE-2016-5270", "CVE-2016-5272",
		"CVE-2016-5274", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278",
		"CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5284");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for thunderbird USN-3112-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Catalin Dumitru discovered that URLs of
  resources loaded after a navigation start could be leaked to the following page
  via the Resource Timing API. If a user were tricked in to opening a specially
  crafted website in a browsing context, an attacker could potentially exploit
  this to obtain sensitive information. (CVE-2016-5250)

Christoph Diehl, Andrew McCreight, Dan Minor, Byron Campen, Jon Coppeard,
Steve Fink, Tyson Smith, and Carsten Book discovered multiple memory
safety issues in Thunderbird. If a user were tricked in to opening a
specially crafted message, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5257)

Atte Kettunen discovered a heap buffer overflow during text conversion
with some unicode characters. If a user were tricked in to opening a
specially crafted message, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5270)

Abhishek Arya discovered a bad cast when processing layout with input
elements in some circumstances. If a user were tricked in to opening a
specially crafted website in a browsing context, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-5272)

A use-after-free was discovered in web animations during restyling. If a
user were tricked in to opening a specially crafted website in a browsing
context, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-5274)

A use-after-free was discovered in accessibility. If a user were tricked
in to opening a specially crafted website in a browsing context, an
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code. (CVE-2016-5276)

A use-after-free was discovered in web animations when destroying a
timeline. If a user were tricked in to opening a specially crafted
website in a browsing context, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5277)

A buffer overflow was discovered when encoding image frames to images in
some circumstances. If a user were tricked in to opening a specially
crafted message, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-5278)

Mei Wang discovered a use-after-free when changing text direction. If  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"thunderbird on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 16.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3112-1/");
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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.4.0+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.4.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.4.0+build1-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

if(release == "UBUNTU16.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.4.0+build1-0ubuntu0.16.10.1", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
