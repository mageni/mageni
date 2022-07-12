###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-2859-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842601");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-14 05:41:08 +0100 (Thu, 14 Jan 2016)");
  script_cve_id("CVE-2015-7201", "CVE-2015-7205", "CVE-2015-7212", "CVE-2015-7213",
                "CVE-2015-7214");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for thunderbird USN-2859-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Andrei Vaida, Jesse Ruderman, Bob Clary,
  and Jesse Ruderman discovered multiple memory safety issues in Thunderbird.
  If a user were tricked in to opening a specially crafted message, an attacker
  could potentially exploit these to cause a denial of service via application
  crash, or execute arbitrary code with the privileges of the user invoking
  Thunderbird. (CVE-2015-7201)

  Ronald Crane discovered a buffer overflow through code inspection. If a
  user were tricked in to opening a specially crafted website in a browsing
  context, an attacker could potentially exploit this to cause a denial of
  service via application crash, or execute arbitrary code with the
  privileges of the user invoking Thunderbird. (CVE-2015-7205)

  Abhishek Arya discovered an integer overflow when allocating large
  textures. If a user were tricked in to opening a specially crafted
  website in a browsing context, an attacker could potentially exploit this
  to cause a denial of service via application crash, or execute arbitrary
  code with the privileges of the user invoking Thunderbird. (CVE-2015-7212)

  Ronald Crane discovered an integer overflow when processing MP4 format
  video in some circumstances. If a user were tricked in to opening a
  specially crafted website in a browsing context, an attacker could
  potentially exploit this to cause a denial of service via application
  crash, or execute arbitrary code with the privileges of the user invoking
  Thunderbird. (CVE-2015-7213)

  Tsubasa Iinuma discovered a way to bypass same-origin restrictions using
  data: and view-source: URLs. If a user were tricked in to opening a
  specially crafted website in a browsing context, an attacker could
  potentially exploit this to obtain sensitive information and read local
  files. (CVE-2015-7214)");
  script_tag(name:"affected", value:"thunderbird on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2859-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(15\.04|14\.04 LTS|12\.04 LTS|15\.10)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU15.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.5.1+build2-0ubuntu0.15.04.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.5.1+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.5.1+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.5.1+build2-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
