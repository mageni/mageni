###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1820_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for gpsd USN-1820-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841419");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-05-09 10:26:27 +0530 (Thu, 09 May 2013)");
  script_cve_id("CVE-2013-2038");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Ubuntu Update for gpsd USN-1820-1");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1820-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gpsd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04 LTS");
  script_tag(name:"affected", value:"gpsd on Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"It was discovered that gpsd incorrectly handled certain malformed GPS data.
  An attacker could use this issue to cause gpsd to crash, resulting in a
  denial of service, or possibly execute arbitrary code.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
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

## gpsd version is made 3.4-2 instead of 3.4-2ubuntu0.1
if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"gpsd", ver:"3.4-2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
