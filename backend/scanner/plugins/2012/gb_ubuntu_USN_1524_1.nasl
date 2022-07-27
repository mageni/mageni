###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1524_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for webkit USN-1524-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1524-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841100");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-09 10:21:55 +0530 (Thu, 09 Aug 2012)");
  script_cve_id("CVE-2011-3046", "CVE-2011-3050", "CVE-2011-3067", "CVE-2011-3068",
                "CVE-2011-3069", "CVE-2011-3071", "CVE-2011-3073", "CVE-2011-3074",
                "CVE-2011-3075", "CVE-2011-3078", "CVE-2012-0672", "CVE-2012-3615",
                "CVE-2012-3655", "CVE-2012-3656", "CVE-2012-3680");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for webkit USN-1524-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1524-1");
  script_tag(name:"affected", value:"webkit on Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"A large number of security issues were discovered in the WebKit browser and
  JavaScript engines. If a user were tricked into viewing a malicious
  website, a remote attacker could exploit a variety of issues related to web
  browser security, including cross-site scripting attacks, denial of
  service attacks, and arbitrary code execution.");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-1.0-0", ver:"1.8.1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-3.0-0", ver:"1.8.1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-1.0-0", ver:"1.8.1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-3.0-0", ver:"1.8.1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
