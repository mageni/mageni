###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1185_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for thunderbird USN-1185-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1185-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840731");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-27 16:37:49 +0200 (Sat, 27 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-2982", "CVE-2011-2981", "CVE-2011-0084", "CVE-2011-2984", "CVE-2011-2378", "CVE-2011-2983");
  script_name("Ubuntu Update for thunderbird USN-1185-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1185-1");
  script_tag(name:"affected", value:"thunderbird on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Gary Kwong, Igor Bukanov, and Bob Clary discovered multiple memory
  vulnerabilities in the Gecko rendering engine. An attacker could use
  these to possibly execute arbitrary code with the privileges of the user
  invoking Thunderbird. (CVE-2011-2982)

  It was discovered that a vulnerability in event management code could
  permit JavaScript to be run in the wrong context. This could potentially
  allow a malicious website to run code as another website or with escalated
  privileges in a chrome-privileged context. (CVE-2011-2981)

  It was discovered that an SVG text manipulation routine contained a
  dangling pointer vulnerability. An attacker could potentially use this to
  crash Thunderbird or execute arbitrary code with the privileges of the user
  invoking Thunderbird. (CVE-2011-0084)

  It was discovered that web content could receive chrome privileges if it
  registered for drop events and a browser tab element was dropped into the
  content area. This could potentially allow a malicious website to run code
  with escalated privileges within Thunderbird. (CVE-2011-2984)

  It was discovered that appendChild contained a dangling pointer
  vulnerability. An attacker could potentially use this to crash Thunderbird
  or execute arbitrary code with the privileges of the user invoking
  Thunderbird. (CVE-2011-2378)

  It was discovered that data from other domains could be read when
  RegExp.input was set. This could potentially allow a malicious website
  access to private data from other domains. (CVE-2011-2983)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.12+build1+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.12+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.12+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
