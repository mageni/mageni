###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3627_2.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for apache2 USN-3627-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.843516");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-05-08 09:25:09 +0200 (Tue, 08 May 2018)");
  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-1283", "CVE-2018-1301",
                "CVE-2018-1303", "CVE-2018-1312");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for apache2 USN-3627-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-3627-1 fixed vulnerabilities in Apache HTTP Server. This update
provides the corresponding updates for Ubuntu 18.04 LTS.

Original advisory details:

Alex Nichols and Jakob Hirsch discovered that the Apache HTTP Server
mod_authnz_ldap module incorrectly handled missing charset encoding
headers. A remote attacker could possibly use this issue to cause the
server to crash, resulting in a denial of service. (CVE-2017-15710)
Elar Lang discovered that the Apache HTTP Server incorrectly handled
certain characters specified in  FilesMatch . A remote attacker could
possibly use this issue to upload certain files, contrary to expectations.
(CVE-2017-15715)
It was discovered that the Apache HTTP Server mod_session module
incorrectly handled certain headers. A remote attacker could possibly use
this issue to influence session data. (CVE-2018-1283)
Robert Swiecki discovered that the Apache HTTP Server incorrectly handled
certain requests. A remote attacker could possibly use this issue to cause
the server to crash, leading to a denial of service. (CVE-2018-1301)
Robert Swiecki discovered that the Apache HTTP Server mod_cache_socache
module incorrectly handled certain headers. A remote attacker could
possibly use this issue to cause the server to crash, leading to a denial
of service. (CVE-2018-1303)
Nicolas Daniels discovered that the Apache HTTP Server incorrectly
generated the nonce when creating HTTP Digest authentication challenges.
A remote attacker could possibly use this issue to replay HTTP requests
across a cluster of servers. (CVE-2018-1312)");
  script_tag(name:"affected", value:"apache2 on Ubuntu 18.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3627-2/");
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
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.29-1ubuntu4.1", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
