###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3538_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for openssh USN-3538-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843425");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-23 07:38:02 +0100 (Tue, 23 Jan 2018)");
  script_cve_id("CVE-2016-10009", "CVE-2016-10010", "CVE-2016-10011", "CVE-2016-10012",
                "CVE-2017-15906");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for openssh USN-3538-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Jann Horn discovered that OpenSSH
  incorrectly loaded PKCS#11 modules from untrusted directories. A remote attacker
  could possibly use this issue to execute arbitrary PKCS#11 modules. This issue
  only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-10009) Jann Horn
  discovered that OpenSSH incorrectly handled permissions on Unix-domain sockets
  when privilege separation is disabled. A local attacker could possibly use this
  issue to gain privileges. This issue only affected Ubuntu 16.04 LTS.
  (CVE-2016-10010) Jann Horn discovered that OpenSSH incorrectly handled certain
  buffer memory operations. A local attacker could possibly use this issue to
  obtain sensitive information. This issue only affected Ubuntu 14.04 LTS and
  Ubuntu 16.04 LTS. (CVE-2016-10011) Guido Vranken discovered that OpenSSH
  incorrectly handled certain shared memory manager operations. A local attacker
  could possibly use issue to gain privileges. This issue only affected Ubuntu
  14.04 LTS and Ubuntu 16.04 LTS. This issue only affected Ubuntu 14.04 LTS and
  Ubuntu 16.04 LTS. (CVE-2016-10012) Michal Zalewski discovered that OpenSSH
  incorrectly prevented write operations in readonly mode. A remote attacker could
  possibly use this issue to create zero-length files, leading to a denial of
  service. (CVE-2017-15906)");
  script_tag(name:"affected", value:"openssh on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3538-1/");
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

  if ((res = isdpkgvuln(pkg:"openssh-server", ver:"1:6.6p1-2ubuntu2.10", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"openssh-server", ver:"1:7.5p1-10ubuntu0.1", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openssh-server", ver:"1:7.2p2-4ubuntu2.4", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
