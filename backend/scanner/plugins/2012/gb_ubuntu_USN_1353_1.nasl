###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1353_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for xulrunner-1.9.2 USN-1353-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1353-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840888");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-13 16:30:21 +0530 (Mon, 13 Feb 2012)");
  script_cve_id("CVE-2012-0442", "CVE-2011-3659", "CVE-2012-0444", "CVE-2012-0449", "CVE-2011-3670");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for xulrunner-1.9.2 USN-1353-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|10\.10)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1353-1");
  script_tag(name:"affected", value:"xulrunner-1.9.2 on Ubuntu 10.10,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Jesse Ruderman and Bob Clary discovered memory safety issues affecting the
  Gecko Browser engine. If the user were tricked into opening a specially
  crafted page, an attacker could exploit these to cause a denial of service
  via application crash, or potentially execute code with the privileges of
  the user invoking Xulrunner. (CVE-2012-0442)

  It was discovered that the Gecko Browser engine did not properly handle
  node removal in the DOM. If the user were tricked into opening a specially
  crafted page, an attacker could exploit this to cause a denial of service
  via application crash, or potentially execute code with the privileges of
  the user invoking Xulrunner. (CVE-2011-3659)

  It was discovered that memory corruption could occur during the decoding of
  Ogg Vorbis files. If the user were tricked into opening a specially crafted
  file, an attacker could exploit this to cause a denial of service via
  application crash, or potentially execute code with the privileges of the
  user invoking Xulrunner. (CVE-2012-0444)

  Nicolas Gregoire and Aki Helin discovered that when processing a malformed
  embedded XSLT stylesheet, Xulrunner can crash due to memory corruption. If
  the user were tricked into opening a specially crafted page, an attacker
  could exploit this to cause a denial of service via application crash, or
  potentially execute code with the privileges of the user invoking Xulrunner.
  (CVE-2012-0449)

  Gregory Fleischer discovered that requests using IPv6 hostname syntax
  through certain proxies might generate errors. An attacker might be able to
  use this to read sensitive data from the error messages. (CVE-2011-3670)");
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

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.26+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.26+build2+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
