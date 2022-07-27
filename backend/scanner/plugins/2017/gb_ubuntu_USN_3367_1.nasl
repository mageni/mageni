###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3367_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for gdb USN-3367-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843257");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-07-27 07:15:47 +0200 (Thu, 27 Jul 2017)");
  script_cve_id("CVE-2014-8501", "CVE-2014-9939", "CVE-2016-2226", "CVE-2016-4487",
                "CVE-2016-4488", "CVE-2016-4489", "CVE-2016-4490", "CVE-2016-4492",
                "CVE-2016-4493", "CVE-2016-6131", "CVE-2016-4491");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for gdb USN-3367-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Hanno Bck discovered that gdb
  incorrectly handled certain malformed AOUT headers in PE executables. If a user
  or automated system were tricked into processing a specially crafted binary, a
  remote attacker could use this issue to cause gdb to crash, resulting in a
  denial of service, or possibly execute arbitrary code. This issue only applied
  to Ubuntu 14.04 LTS. (CVE-2014-8501) It was discovered that gdb incorrectly
  handled printing bad bytes in Intel Hex objects. If a user or automated system
  were tricked into processing a specially crafted binary, a remote attacker could
  use this issue to cause gdb to crash, resulting in a denial of service. This
  issue only applied to Ubuntu 14.04 LTS. (CVE-2014-9939) It was discovered that
  gdb incorrectly handled certain string operations. If a user or automated system
  were tricked into processing a specially crafted binary, a remote attacker could
  use this issue to cause gdb to crash, resulting in a denial of service, or
  possibly execute arbitrary code. This issue only applied to Ubuntu 14.04 LTS and
  Ubuntu 16.04 LTS. (CVE-2016-2226) It was discovered that gdb incorrectly handled
  parsing certain binaries. If a user or automated system were tricked into
  processing a specially crafted binary, a remote attacker could use this issue to
  cause gdb to crash, resulting in a denial of service. This issue only applied to
  Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-4487, CVE-2016-4488,
  CVE-2016-4489, CVE-2016-4490, CVE-2016-4492, CVE-2016-4493, CVE-2016-6131) It
  was discovered that gdb incorrectly handled parsing certain binaries. If a user
  or automated system were tricked into processing a specially crafted binary, a
  remote attacker could use this issue to cause gdb to crash, resulting in a
  denial of service. (CVE-2016-4491)");
  script_tag(name:"affected", value:"gdb on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3367-1/");
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

  if ((res = isdpkgvuln(pkg:"gdb", ver:"7.7.1-0ubuntu5~14.04.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"gdb", ver:"7.12.50.20170314-0ubuntu1.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"gdb", ver:"7.11.1-0ubuntu1~16.5", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
