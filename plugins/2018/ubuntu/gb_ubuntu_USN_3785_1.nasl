###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3785_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for imagemagick USN-3785-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843653");
  script_version("$Revision: 14288 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-05 08:17:46 +0200 (Fri, 05 Oct 2018)");
  script_cve_id("CVE-2018-14434", "CVE-2018-14435", "CVE-2018-14436", "CVE-2018-14437",
                "CVE-2018-16640", "CVE-2018-16750", "CVE-2018-14551", "CVE-2018-16323",
                "CVE-2018-16642", "CVE-2018-16643", "CVE-2018-16644", "CVE-2018-16645",
                "CVE-2018-16749", "CVE-2017-13144");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for imagemagick USN-3785-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
present on the target host.");
  script_tag(name:"insight", value:"Due to a large number of issues discovered
in GhostScript that prevent it from being used by ImageMagick safely, this update
includes a default policy change that disables support for the Postscript and
PDF formats in ImageMagick. This policy can be overridden if necessary
by using an alternate ImageMagick policy configuration.

It was discovered that several memory leaks existed when handling
certain images in ImageMagick. An attacker could use this to cause a
denial of service. (CVE-2018-14434, CVE-2018-14435, CVE-2018-14436,
CVE-2018-14437, CVE-2018-16640, CVE-2018-16750)

It was discovered that ImageMagick did not properly initialize a
variable before using it when processing MAT images. An attacker could
use this to cause a denial of service or possibly execute arbitrary
code. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-14551)

It was discovered that an information disclosure vulnerability existed
in ImageMagick when processing XBM images. An attacker could use this
to expose sensitive information. (CVE-2018-16323)

It was discovered that an out-of-bounds write vulnerability existed
in ImageMagick when handling certain images. An attacker could use
this to cause a denial of service or possibly execute arbitrary code.
(CVE-2018-16642)

It was discovered that ImageMagick did not properly check for errors
in some situations. An attacker could use this to cause a denial of
service. (CVE-2018-16643)

It was discovered that ImageMagick did not properly validate image
meta data in some situations. An attacker could use this to cause a
denial of service. (CVE-2018-16644)

It was discovered that ImageMagick did not prevent excessive memory
allocation when handling certain image types. An attacker could use
this to cause a denial of service. (CVE-2018-16645)

Sergej Schumilo and Cornelius Aschermann discovered that ImageMagick
did not properly check for NULL in some situations when processing
PNG images. An attacker could use this to cause a denial of service.
(CVE-2018-16749)

USN-3681-1 fixed vulnerabilities in Imagemagick. Unfortunately,
the fix for CVE-2017-13144 introduced a regression in ImageMagick in
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. This update reverts the fix
for CVE-2017-13144 for those releases.

We apologize for the inconvenience.");
  script_tag(name:"affected", value:"imagemagick on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3785-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|18\.04 LTS|16\.04 LTS)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.7.7.10-6ubuntu3.13", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagick++5", ver:"8:6.7.7.10-6ubuntu3.13", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore5", ver:"8:6.7.7.10-6ubuntu3.13", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore5-extra", ver:"8:6.7.7.10-6ubuntu3.13", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.7.4+dfsg-16ubuntu6.4", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.7.4+dfsg-16ubuntu6.4", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagick++-6.q16-7", ver:"8:6.9.7.4+dfsg-16ubuntu6.4", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore-6.q16-3", ver:"8:6.9.7.4+dfsg-16ubuntu6.4", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore-6.q16-3-extra", ver:"8:6.9.7.4+dfsg-16ubuntu6.4", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.8.9.9-7ubuntu5.13", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.8.9.9-7ubuntu5.13", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagick++-6.q16-5v5", ver:"8:6.8.9.9-7ubuntu5.13", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore-6.q16-2", ver:"8:6.8.9.9-7ubuntu5.13", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore-6.q16-2-extra", ver:"8:6.8.9.9-7ubuntu5.13", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
