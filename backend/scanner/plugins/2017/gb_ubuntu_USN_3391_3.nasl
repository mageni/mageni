###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3391_3.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for firefox USN-3391-3
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843288");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-08-18 07:32:37 +0200 (Fri, 18 Aug 2017)");
  script_cve_id("CVE-2017-7753", "CVE-2017-7779", "CVE-2017-7780", "CVE-2017-7781",
                "CVE-2017-7783", "CVE-2017-7784", "CVE-2017-7785", "CVE-2017-7786",
                "CVE-2017-7787", "CVE-2017-7788", "CVE-2017-7789", "CVE-2017-7791",
                "CVE-2017-7792", "CVE-2017-7794", "CVE-2017-7797", "CVE-2017-7798",
                "CVE-2017-7799", "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7802",
                "CVE-2017-7803", "CVE-2017-7806", "CVE-2017-7807", "CVE-2017-7808",
                "CVE-2017-7809");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for firefox USN-3391-3");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-3391-1 fixed vulnerabilities in Firefox.
  The update introduced a performance regression with WebExtensions. This update
  fixes the problem. We apologize for the inconvenience. Original advisory
  details: Multiple security issues were discovered in Firefox. If a user were
  tricked in to opening a specially crafted website, an attacker could potentially
  exploit these to conduct cross-site scripting (XSS) attacks, bypass sandbox
  restrictions, obtain sensitive information, spoof the origin of modal alerts,
  bypass same origin restrictions, read uninitialized memory, cause a denial of
  service via program crash or hang, or execute arbitrary code. (CVE-2017-7753,
  CVE-2017-7779, CVE-2017-7780, CVE-2017-7781, CVE-2017-7783, CVE-2017-7784,
  CVE-2017-7785, CVE-2017-7786, CVE-2017-7787, CVE-2017-7788, CVE-2017-7789,
  CVE-2017-7791, CVE-2017-7792, CVE-2017-7794, CVE-2017-7797, CVE-2017-7798,
  CVE-2017-7799, CVE-2017-7800, CVE-2017-7801, CVE-2017-7802, CVE-2017-7803,
  CVE-2017-7806, CVE-2017-7807, CVE-2017-7808, CVE-2017-7809)");
  script_tag(name:"affected", value:"firefox on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3391-3/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.04|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"55.0.2+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"55.0.2+build1-0ubuntu0.17.04.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"55.0.2+build1-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
