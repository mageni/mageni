###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1479_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for ffmpeg USN-1479-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1479-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841048");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-19 09:42:08 +0530 (Tue, 19 Jun 2012)");
  script_cve_id("CVE-2011-3929", "CVE-2011-3936", "CVE-2011-3940", "CVE-2011-3947",
                "CVE-2011-3951", "CVE-2011-3952", "CVE-2012-0851", "CVE-2012-0852",
                "CVE-2012-0853", "CVE-2012-0858", "CVE-2012-0859", "CVE-2012-0947");
  script_name("Ubuntu Update for ffmpeg USN-1479-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1479-1");
  script_tag(name:"affected", value:"ffmpeg on Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg incorrectly
  handled certain malformed DV files. If a user were tricked into opening a
  crafted DV file, an attacker could cause a denial of service via
  application crash, or possibly execute arbitrary code with the privileges
  of the user invoking the program. (CVE-2011-3929, CVE-2011-3936)

  Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg incorrectly
  handled certain malformed NSV files. If a user were tricked into opening a
  crafted NSV file, an attacker could cause a denial of service via
  application crash, or possibly execute arbitrary code with the privileges
  of the user invoking the program. (CVE-2011-3940)

  Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg incorrectly
  handled certain malformed MJPEG-B files. If a user were tricked into
  opening a crafted MJPEG-B file, an attacker could cause a denial of service
  via application crash, or possibly execute arbitrary code with the
  privileges of the user invoking the program. (CVE-2011-3947)

  Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg incorrectly
  handled certain malformed DPCM files. If a user were tricked into opening a
  crafted DPCM file, an attacker could cause a denial of service via
  application crash, or possibly execute arbitrary code with the privileges
  of the user invoking the program. (CVE-2011-3951)

  Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg incorrectly
  handled certain malformed KMVC files. If a user were tricked into opening a
  crafted KMVC file, an attacker could cause a denial of service via
  application crash, or possibly execute arbitrary code with the privileges
  of the user invoking the program. (CVE-2011-3952)

  It was discovered that FFmpeg incorrectly handled certain malformed H.264
  files. If a user were tricked into opening a crafted H.264 file, an
  attacker could cause a denial of service via application crash, or possibly
  execute arbitrary code with the privileges of the user invoking the
  program. (CVE-2012-0851)

  It was discovered that FFmpeg incorrectly handled certain malformed ADPCM
  files. If a user were tricked into opening a crafted ADPCM file, an
  attacker could cause a denial of service via application crash, or possibly
  execute arbitrary code with the privileges of the user invoking the
  program. (CVE-2012-0852)

  It was discovered that FFmpeg incorrectly handled certain malformed Atrac 3
  files. If a user were tricked into opening a crafted Atrac 3 file, an
  attacker could cause a denial of service via application crash, ...

  Description truncated, please see the referenced URL(s) for more information.");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libavcodec52", ver:"0.5.9-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat52", ver:"0.5.9-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
