###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-3044-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842847");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-06 05:36:37 +0200 (Sat, 06 Aug 2016)");
  script_cve_id("CVE-2016-0718", "CVE-2016-2830", "CVE-2016-2835", "CVE-2016-2836",
		"CVE-2016-2837", "CVE-2016-2838", "CVE-2016-2839", "CVE-2016-5250",
		"CVE-2016-5251", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5255",
		"CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5260", "CVE-2016-5261",
		"CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265",
		"CVE-2016-5266", "CVE-2016-5268");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for firefox USN-3044-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Gustavo Grieco discovered an out-of-bounds
  read during XML parsing in some circumstances. If a user were tricked in to
  opening a specially crafted website, an attacker could potentially exploit this
  to cause a denial of service via application crash, or obtain sensitive
  information. (CVE-2016-0718)

Toni Huttunen discovered that once a favicon is requested from a site,
the remote server can keep the network connection open even after the page
is closed. A remote attacked could potentially exploit this to track
users, resulting in information disclosure. (CVE-2016-2830)

Christian Holler, Tyson Smith, Boris Zbarsky, Byron Campen, Julian Seward,
Carsten Book, Gary Kwong, Jesse Ruderman, Andrew McCreight, and Phil
Ringnalda discovered multiple memory safety issues in Firefox. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-2835, CVE-2016-2836)

A buffer overflow was discovered in the ClearKey Content Decryption
Module (CDM) during video playback. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit this to
cause a denial of service via plugin process crash, or, in combination
with another vulnerability to escape the GMP sandbox, execute arbitrary
code. (CVE-2016-2837)

Atte Kettunen discovered a buffer overflow when rendering SVG content in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-2838)

Bert Massop discovered a crash in Cairo with version 0.10 of FFmpeg. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to execute arbitrary code. (CVE-2016-2839)

Catalin Dumitru discovered that URLs of resources loaded after a
navigation start could be leaked to the following page via the Resource
Timing API. An attacker could potentially exploit this to obtain sensitive
information. (CVE-2016-5250)

Firas Salem discovered an issue with non-ASCII and emoji characters in
data: URLs. An attacker could potentially exploit this to spoof the
addressbar contents. (CVE-2016-5251)

Georg Koppen discovered a stack buffer underflow during 2D graphics
rendering in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
cause a denial of service via application crash, or ex ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"firefox on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3044-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"48.0+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"48.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"48.0+build2-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
