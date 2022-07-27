###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3707_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for ntp USN-3707-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843586");
  script_version("$Revision: 14288 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-07-10 05:56:31 +0200 (Tue, 10 Jul 2018)");
  script_cve_id("CVE-2018-7182", "CVE-2018-7183", "CVE-2018-7184", "CVE-2018-7185");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for ntp USN-3707-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Yihan Lian discovered that NTP incorrectly handled certain malformed mode 6
packets. A remote attacker could possibly use this issue to cause ntpd to
crash, resulting in a denial of service. This issue only affected Ubuntu
17.10 and Ubuntu 18.04 LTS. (CVE-2018-7182)

Michael Macnair discovered that NTP incorrectly handled certain responses.
A remote attacker could possibly use this issue to execute arbitrary code.
(CVE-2018-7183)

Miroslav Lichvar discovered that NTP incorrectly handled certain
zero-origin timestamps. A remote attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 17.10 and Ubuntu
18.04 LTS. (CVE-2018-7184)

Miroslav Lichvar discovered that NTP incorrectly handled certain
zero-origin timestamps. A remote attacker could possibly use this issue to
cause a denial of service. (CVE-2018-7185)");
  script_tag(name:"affected", value:"ntp on Ubuntu 18.04 LTS,
  Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3707-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.10|18\.04 LTS|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-3ubuntu2.14.04.13", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p10+dfsg-5ubuntu3.3", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p10+dfsg-5ubuntu7.1", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p4+dfsg-3ubuntu5.9", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
