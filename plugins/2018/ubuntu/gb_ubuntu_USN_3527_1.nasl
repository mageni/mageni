###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3527_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for irssi USN-3527-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843417");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-11 07:38:51 +0100 (Thu, 11 Jan 2018)");
  script_cve_id("CVE-2018-5205", "CVE-2018-5206", "CVE-2018-5207", "CVE-2018-5208");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for irssi USN-3527-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'irssi'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Joseph Bisch discovered that Irssi
  incorrectly handled incomplete escape codes. If a user were tricked into using
  malformed commands or opening malformed files, an attacker could use this issue
  to cause Irssi to crash, resulting in a denial of service. (CVE-2018-5205)
  Joseph Bisch discovered that Irssi incorrectly handled settings the channel
  topic without specifying a sender. A malicious IRC server could use this issue
  to cause Irssi to crash, resulting in a denial of service. (CVE-2018-5206)
  Joseph Bisch discovered that Irssi incorrectly handled incomplete variable
  arguments. If a user were tricked into using malformed commands or opening
  malformed files, an attacker could use this issue to cause Irssi to crash,
  resulting in a denial of service. (CVE-2018-5207) Joseph Bisch discovered that
  Irssi incorrectly handled completing certain strings. An attacker could use this
  issue to cause Irssi to crash, resulting in a denial of service, or possibly
  execute arbitrary code. (CVE-2018-5208)");
  script_tag(name:"affected", value:"irssi on Ubuntu 17.10,
  Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3527-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.10|17\.04|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.15-5ubuntu3.4", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"irssi", ver:"1.0.4-1ubuntu2.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.20-2ubuntu2.3", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.19-1ubuntu1.6", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
