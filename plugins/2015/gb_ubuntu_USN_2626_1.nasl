###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for qt4-x11 USN-2626-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842217");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-09 11:07:43 +0200 (Tue, 09 Jun 2015)");
  script_cve_id("CVE-2014-0190", "CVE-2015-0295", "CVE-2015-1858", "CVE-2015-1859",
                "CVE-2015-1860");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for qt4-x11 USN-2626-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt4-x11'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Wolfgang Schenk discovered that Qt
incorrectly handled certain malformed GIF images. If a user or automated
system were tricked into opening a specially crafted GIF image, a remote attacker
could use this issue to cause Qt to crash, resulting in a denial of service. This
issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-0190)

Fabian Vogt discovered that Qt incorrectly handled certain malformed BMP
images. If a user or automated system were tricked into opening a specially
crafted BMP image, a remote attacker could use this issue to cause Qt to
crash, resulting in a denial of service. (CVE-2015-0295)

Richard Moore and Fabian Vogt discovered that Qt incorrectly handled
certain malformed BMP images. If a user or automated system were tricked
into opening a specially crafted BMP image, a remote attacker could use
this issue to cause Qt to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2015-1858)

Richard Moore and Fabian Vogt discovered that Qt incorrectly handled
certain malformed ICO images. If a user or automated system were tricked
into opening a specially crafted ICO image, a remote attacker could use
this issue to cause Qt to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2015-1859)

Richard Moore and Fabian Vogt discovered that Qt incorrectly handled
certain malformed GIF images. If a user or automated system were tricked
into opening a specially crafted GIF image, a remote attacker could use
this issue to cause Qt to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2015-1860)");
  script_tag(name:"affected", value:"qt4-x11 on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2626-1/");
  script_tag(name:"solution_type", value:"VendorFix");
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

  if ((res = isdpkgvuln(pkg:"libqt5gui5:amd64", ver:"5.3.0+dfsg-2ubuntu9.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"libqt5gui5:i386", ver:"5.3.0+dfsg-2ubuntu9.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }


  if ((res = isdpkgvuln(pkg:"libqtgui4:amd64", ver:"4:4.8.6+git49-gbc62005+dfsg-1ubuntu1.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"libqtgui4:i386", ver:"4:4.8.6+git49-gbc62005+dfsg-1ubuntu1.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }


  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libqt5gui5:amd64", ver:"5.2.1+dfsg-1ubuntu14.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"libqt5gui5:i386", ver:"5.2.1+dfsg-1ubuntu14.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libqtgui4:amd64", ver:"4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libqtgui4:i386", ver:"4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libqtgui4", ver:"4:4.8.1-0ubuntu4.9", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
