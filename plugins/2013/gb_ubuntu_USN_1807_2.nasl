###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1807_2.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for mysql-5.5 USN-1807-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.841410");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-06-14 12:49:04 +0530 (Fri, 14 Jun 2013)");
  script_cve_id("CVE-2012-0553", "CVE-2013-1492", "CVE-2013-1502", "CVE-2013-1506",
                "CVE-2013-1511", "CVE-2013-1512", "CVE-2013-1521", "CVE-2013-1523",
                "CVE-2013-1526", "CVE-2013-1532", "CVE-2013-1544", "CVE-2013-1552",
                "CVE-2013-1555", "CVE-2013-1623", "CVE-2013-2375", "CVE-2013-2376",
                "CVE-2013-2378", "CVE-2013-2389", "CVE-2013-2391", "CVE-2013-2392");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for mysql-5.5 USN-1807-2");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1807-2/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.5'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.04");
  script_tag(name:"affected", value:"mysql-5.5 on Ubuntu 13.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1807-1 fixed vulnerabilities in MySQL. This update provides
  MySQL 5.5.31 for Ubuntu 13.04.

  Original advisory details:

  Multiple security issues were discovered in MySQL and this update includes
  new upstream MySQL versions to fix these issues.

  MySQL has been updated to 5.1.69 in Ubuntu 10.04 LTS and Ubuntu 11.10.
  Ubuntu 12.04 LTS and Ubuntu 12.10 have been updated to MySQL 5.5.31.

  In addition to security fixes, the updated packages contain bug fixes,
  new features, and possibly incompatible changes.

  Please see the references for more information.");

  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-69.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-31.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html");

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

if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.31-0ubuntu0.13.04.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
