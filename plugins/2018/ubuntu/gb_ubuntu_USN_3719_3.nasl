###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3719_3.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for mutt USN-3719-3
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
  script_oid("1.3.6.1.4.1.25623.1.0.843642");
  script_version("$Revision: 14288 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-28 08:19:24 +0200 (Fri, 28 Sep 2018)");
  script_cve_id("CVE-2018-14350", "CVE-2018-14352", "CVE-2018-14354", "CVE-2018-14359",
                "CVE-2018-14358", "CVE-2018-14353", "CVE-2018-14357", "CVE-2018-14355",
                "CVE-2018-14356", "CVE-2018-14351", "CVE-2018-14362", "CVE-2018-14349");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for mutt USN-3719-3");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mutt'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"USN-3719-1 fixed vulnerabilities in Mutt.
Unfortunately, the fixes were not correctly applied to the packaging for Mutt in
Ubuntu 16.04 LTS. This update corrects the oversight.

We apologize for the inconvenience.

Original advisory details:

It was discovered that Mutt incorrectly handled certain requests.
An attacker could possibly use this to execute arbitrary code.
(CVE-2018-14350, CVE-2018-14352, CVE-2018-14354, CVE-2018-14359,
CVE-2018-14358, CVE-2018-14353, CVE-2018-14357)

It was discovered that Mutt incorrectly handled certain inputs.
An attacker could possibly use this to access or expose sensitive
information. (CVE-2018-14355, CVE-2018-14356, CVE-2018-14351,
CVE-2018-14362, CVE-2018-14349)");
  script_tag(name:"affected", value:"mutt on Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3719-3/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"mutt", ver:"1.5.24-1ubuntu0.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mutt-patched", ver:"1.5.24-1ubuntu0.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
