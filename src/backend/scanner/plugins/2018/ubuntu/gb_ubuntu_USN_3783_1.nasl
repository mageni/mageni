###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3783_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for apache2 USN-3783-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843652");
  script_version("$Revision: 14288 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-04 08:32:19 +0200 (Thu, 04 Oct 2018)");
  script_cve_id("CVE-2018-1302", "CVE-2018-1333", "CVE-2018-11763");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for apache2 USN-3783-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
present on the target host.");
  script_tag(name:"insight", value:"Robert Swiecki discovered that the
Apache HTTP Server HTTP/2 module incorrectly destroyed certain streams.
A remote attacker could possibly use this issue to cause the server to
crash, leading to a denial of service. (CVE-2018-1302)

Craig Young discovered that the Apache HTTP Server HTTP/2 module
incorrectly handled certain requests. A remote attacker could possibly
use this issue to cause the server to consume resources, leading to a
denial of service. (CVE-2018-1333)

Gal Goldshtein discovered that the Apache HTTP Server HTTP/2 module
incorrectly handled large SETTINGS frames. A remote attacker could possibly
use this issue to cause the server to consume resources, leading to a
denial of service. (CVE-2018-11763)");
  script_tag(name:"affected", value:"apache2 on Ubuntu 18.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3783-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04 LTS");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.29-1ubuntu4.4", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
