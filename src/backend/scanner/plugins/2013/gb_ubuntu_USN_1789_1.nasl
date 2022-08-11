###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1789_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for postgresql-9.1 USN-1789-1
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
  script_tag(name:"affected", value:"postgresql-9.1 on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mitsumasa Kondo and Kyotaro Horiguchi discovered that PostgreSQL
  incorrectly handled certain connection requests containing database names
  starting with a dash. A remote attacker could use this flaw to damage or
  destroy files within a server's data directory. This issue only applied to
  Ubuntu 11.10, Ubuntu 12.04 LTS, and Ubuntu 12.10. (CVE-2013-1899)

  Marko Kreen discovered that PostgreSQL incorrectly generated random
  numbers. An authenticated attacker could use this flaw to possibly guess
  another database user's random numbers. (CVE-2013-1900)

  Noah Misch discovered that PostgreSQL incorrectly handled certain privilege
  checks. An unprivileged attacker could use this flaw to possibly interfere
  with in-progress backups. This issue only applied to Ubuntu 11.10,
  Ubuntu 12.04 LTS, and Ubuntu 12.10. (CVE-2013-1901)");
  script_oid("1.3.6.1.4.1.25623.1.0.841385");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-04-05 13:51:38 +0530 (Fri, 05 Apr 2013)");
  script_cve_id("CVE-2013-1899", "CVE-2013-1900", "CVE-2013-1901");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Ubuntu Update for postgresql-9.1 USN-1789-1");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1789-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-9.1'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|11\.10|10\.04 LTS|8\.04 LTS|12\.10)");

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

  if ((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.9-0ubuntu12.04", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.9-0ubuntu11.10", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"postgresql-8.4", ver:"8.4.17-0ubuntu10.04", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.23-0ubuntu8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.9-0ubuntu12.10", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
