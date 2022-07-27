###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3681_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for imagemagick USN-3681-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843556");
  script_version("$Revision: 14288 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-06-13 05:45:46 +0200 (Wed, 13 Jun 2018)");
  script_cve_id("CVE-2017-1000445", "CVE-2017-1000476", "CVE-2017-10995", "CVE-2018-6405",
                "CVE-2017-11352", "CVE-2017-11533", "CVE-2017-11535", "CVE-2017-11537",
                "CVE-2017-11639", "CVE-2017-11640", "CVE-2017-12140", "CVE-2017-12418",
                "CVE-2017-12429", "CVE-2017-12430", "CVE-2017-12431", "CVE-2017-12432",
                "CVE-2017-12433", "CVE-2017-12435", "CVE-2017-12563", "CVE-2017-12587",
                "CVE-2017-12640", "CVE-2017-12643", "CVE-2017-12644", "CVE-2017-12670",
                "CVE-2017-12674", "CVE-2017-12691", "CVE-2017-12692", "CVE-2017-12693",
                "CVE-2017-12875", "CVE-2017-12877", "CVE-2017-12983", "CVE-2017-13058",
                "CVE-2017-13059", "CVE-2017-13060", "CVE-2017-13061", "CVE-2017-13062",
                "CVE-2017-13131", "CVE-2017-13134", "CVE-2017-13139", "CVE-2017-13142",
                "CVE-2017-13143", "CVE-2017-13144", "CVE-2017-13145", "CVE-2017-13758",
                "CVE-2017-13768", "CVE-2017-13769", "CVE-2017-14060", "CVE-2017-14172",
                "CVE-2017-14173", "CVE-2017-14174", "CVE-2017-14175", "CVE-2017-14224",
                "CVE-2017-14249", "CVE-2017-14325", "CVE-2017-14326", "CVE-2017-14341",
                "CVE-2017-14342", "CVE-2017-14343", "CVE-2017-14400", "CVE-2017-14505",
                "CVE-2017-14531", "CVE-2017-14532", "CVE-2017-14533", "CVE-2017-14607",
                "CVE-2017-14624", "CVE-2017-14625", "CVE-2017-14626", "CVE-2017-14682",
                "CVE-2017-14684", "CVE-2017-14739", "CVE-2017-14741", "CVE-2017-14989",
                "CVE-2017-15015", "CVE-2017-15016", "CVE-2017-15017", "CVE-2017-15032",
                "CVE-2017-15033", "CVE-2017-15217", "CVE-2017-15218", "CVE-2017-15277",
                "CVE-2017-15281", "CVE-2017-16546", "CVE-2017-17499", "CVE-2017-17504",
                "CVE-2017-17680", "CVE-2017-17681", "CVE-2017-17682", "CVE-2017-17879",
                "CVE-2017-17881", "CVE-2017-17882", "CVE-2017-17884", "CVE-2017-17885",
                "CVE-2017-17886", "CVE-2017-17887", "CVE-2017-17914", "CVE-2017-17934",
                "CVE-2017-18008", "CVE-2017-18022", "CVE-2017-18027", "CVE-2017-18028",
                "CVE-2017-18029", "CVE-2017-18209", "CVE-2017-18211", "CVE-2017-18251",
                "CVE-2017-18252", "CVE-2017-18254", "CVE-2017-18271", "CVE-2017-18273",
                "CVE-2018-10177", "CVE-2018-10804", "CVE-2018-10805", "CVE-2018-11251",
                "CVE-2018-11625", "CVE-2018-11655", "CVE-2018-11656", "CVE-2018-5246",
                "CVE-2018-5247", "CVE-2018-5248", "CVE-2018-5357", "CVE-2018-5358",
                "CVE-2018-7443", "CVE-2018-8804", "CVE-2018-8960", "CVE-2018-9133");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for imagemagick USN-3681-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
the target host.");
  script_tag(name:"insight", value:"It was discovered that ImageMagick incorrectly
handled certain malformed image files. If a user or automated system using ImageMagick
were tricked into opening a specially crafted image, an attacker could exploit this to
cause a denial of service or possibly execute code with the privileges of
the user invoking the program.");
  script_tag(name:"affected", value:"imagemagick on Ubuntu 18.04 LTS,
  Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3681-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.10|18\.04 LTS|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.7.7.10-6ubuntu3.11", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagick++5", ver:"8:6.7.7.10-6ubuntu3.11", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore5", ver:"8:6.7.7.10-6ubuntu3.11", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore5-extra", ver:"8:6.7.7.10-6ubuntu3.11", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.7.4+dfsg-16ubuntu2.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.7.4+dfsg-16ubuntu2.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagick++-6.q16-7", ver:"8:6.9.7.4+dfsg-16ubuntu2.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore-6.q16-3", ver:"8:6.9.7.4+dfsg-16ubuntu2.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore-6.q16-3-extra", ver:"8:6.9.7.4+dfsg-16ubuntu2.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.7.4+dfsg-16ubuntu6.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.7.4+dfsg-16ubuntu6.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagick++-6.q16-7", ver:"8:6.9.7.4+dfsg-16ubuntu6.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore-6.q16-3", ver:"8:6.9.7.4+dfsg-16ubuntu6.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore-6.q16-3-extra", ver:"8:6.9.7.4+dfsg-16ubuntu6.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.8.9.9-7ubuntu5.11", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.8.9.9-7ubuntu5.11", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagick++-6.q16-5v5", ver:"8:6.8.9.9-7ubuntu5.11", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore-6.q16-2", ver:"8:6.8.9.9-7ubuntu5.11", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmagickcore-6.q16-2-extra", ver:"8:6.8.9.9-7ubuntu5.11", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
