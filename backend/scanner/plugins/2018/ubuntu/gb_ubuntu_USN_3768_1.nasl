###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3768_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for ghostscript USN-3768-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843638");
  script_version("$Revision: 14288 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-20 07:34:01 +0200 (Thu, 20 Sep 2018)");
  script_cve_id("CVE-2018-11645", "CVE-2018-15908", "CVE-2018-15909",
                  "CVE-2018-15910", "CVE-2018-15911", "CVE-2018-16509", "CVE-2018-16510",
                  "CVE-2018-16511", "CVE-2018-16513", "CVE-2018-16539", "CVE-2018-16540",
                  "CVE-2018-16541", "CVE-2018-16542", "CVE-2018-16543", "CVE-2018-16585",
                "CVE-2018-16802");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for ghostscript USN-3768-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Tavis Ormandy discovered multiple security issues in Ghostscript. If a user
or automated system were tricked into processing a specially crafted file,
a remote attacker could possibly use these issues to access arbitrary
files, execute arbitrary code, or cause a denial of service.");
  script_tag(name:"affected", value:"ghostscript on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3768-1/");
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
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"ghostscript", ver:"9.10~dfsg-0ubuntu10.13", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgs9", ver:"9.10~dfsg-0ubuntu10.13", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"ghostscript", ver:"9.22~dfsg+1-0ubuntu1.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgs9", ver:"9.22~dfsg+1-0ubuntu1.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"ghostscript", ver:"9.18~dfsg~0-0ubuntu2.9", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgs9", ver:"9.18~dfsg~0-0ubuntu2.9", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
