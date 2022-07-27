# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843900");
  script_version("2019-04-26T06:52:17+0000");
  script_cve_id("CVE-2018-10119", "CVE-2018-10120", "CVE-2018-11790", "CVE-2018-10583",
                "CVE-2018-16858");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-26 06:52:17 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-07 04:03:44 +0100 (Thu, 07 Feb 2019)");
  script_name("Ubuntu Update for libreoffice USN-3883-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|16\.04 LTS)");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3883-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice'
  package(s) announced via the USN-3883-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version
is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that LibreOffice incorrectly
handled certain document files. If a user were tricked into opening a specially
crafted document, a remote attacker could cause LibreOffice to crash, and possibly
execute arbitrary code. (CVE-2018-10119, CVE-2018-10120, CVE-2018-11790)

It was discovered that LibreOffice incorrectly handled embedded SMB
connections in document files. If a user were tricked in to opening a
specially crafted document, a remote attacker could possibly exploit this
to obtain sensitive information. (CVE-2018-10583)

Alex Infhr discovered that LibreOffice incorrectly handled embedded
scripts in document files. If a user were tricked into opening a specially
crafted document, a remote attacker could possibly execute arbitrary code.
(CVE-2018-16858)");

  script_tag(name:"affected", value:"libreoffice on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libreoffice-core", ver:"1:4.2.8-0ubuntu5.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libreoffice-core", ver:"1:5.1.6~rc2-0ubuntu1~xenial6", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
