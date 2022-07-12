###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3544_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for firefox USN-3544-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843432");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-25 07:53:36 +0100 (Thu, 25 Jan 2018)");
  script_cve_id("CVE-2018-5089", "CVE-2018-5090", "CVE-2018-5091", "CVE-2018-5092",
                "CVE-2018-5093", "CVE-2018-5094", "CVE-2018-5095", "CVE-2018-5097",
                "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5100", "CVE-2018-5101",
                "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5109",
                "CVE-2018-5114", "CVE-2018-5115", "CVE-2018-5117", "CVE-2018-5122",
                "CVE-2018-5105", "CVE-2018-5113", "CVE-2018-5116", "CVE-2018-5106",
                "CVE-2018-5107", "CVE-2018-5108", "CVE-2018-5111", "CVE-2018-5112",
                "CVE-2018-5118", "CVE-2018-5119");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for firefox USN-3544-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple security issues were discovered in
  Firefox. If a user were tricked in to opening a specially crafted website, an
  attacker could potentially exploit these to cause a denial of service via
  application crash, spoof the origin in audio capture prompts, trick the user in
  to providing HTTP credentials for another origin, spoof the addressbar contents,
  or execute arbitrary code. (CVE-2018-5089, CVE-2018-5090, CVE-2018-5091,
  CVE-2018-5092, CVE-2018-5093, CVE-2018-5094, CVE-2018-5095, CVE-2018-5097,
  CVE-2018-5098, CVE-2018-5099, CVE-2018-5100, CVE-2018-5101, CVE-2018-5102,
  CVE-2018-5103, CVE-2018-5104, CVE-2018-5109, CVE-2018-5114, CVE-2018-5115,
  CVE-2018-5117, CVE-2018-5122) Multiple security issues were discovered in
  WebExtensions. If a user were tricked in to installing a specially crafted
  extension, an attacker could potentially exploit these to gain additional
  privileges, bypass same-origin restrictions, or execute arbitrary code.
  (CVE-2018-5105, CVE-2018-5113, CVE-2018-5116) A security issue was discovered
  with the developer tools. If a user were tricked in to opening a specially
  crafted website with the developer tools open, an attacker could potentially
  exploit this to obtain sensitive information from other origins. (CVE-2018-5106)
  A security issue was discovered with printing. An attacker could potentially
  exploit this to obtain sensitive information from local files. (CVE-2018-5107)
  It was discovered that manually entered blob URLs could be accessed by
  subsequent private browsing tabs. If a user were tricked in to entering a blob
  URL, an attacker could potentially exploit this to obtain sensitive information
  from a private browsing context. (CVE-2018-5108) It was discovered that dragging
  certain specially formatted URLs to the addressbar could cause the wrong URL to
  be displayed. If a user were tricked in to opening a specially crafted website
  and dragging a URL to the addressbar, an attacker could potentially exploit this
  to spoof the addressbar contents. (CVE-2018-5111) It was discovered that
  WebExtension developer tools panels could open non-relative URLs. If a user were
  tricked in to installing a specially crafted extension and running the developer
  tools, an attacker could potentially exploit this to gain additional privileges.
  (CVE-2018-5112) It was discovered that ActivityStream images can attempt to load
  local content through file: URLs. If a user were tricked in to opening a
  specially crafted website, an attacker could potentially exploit this in
  combination with another vulnerability that allowed sandbox protections to be b
  ... Description truncated, for more information please check the Reference
  URL");
  script_tag(name:"affected", value:"firefox on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3544-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.10|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"58.0+build6-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"58.0+build6-0ubuntu0.17.10.1", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"58.0+build6-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
