###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1297_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for python-django USN-1297-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1297-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840830");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-12-09 10:52:57 +0530 (Fri, 09 Dec 2011)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2011-4136", "CVE-2011-4137", "CVE-2011-4138", "CVE-2011-4139");
  script_name("Ubuntu Update for python-django USN-1297-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1297-1");
  script_tag(name:"affected", value:"python-django on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Pall McMillan discovered that Django used the root namespace when storing
  cached session data. A remote attacker could exploit this to modify
  sessions. (CVE-2011-4136)

  Paul McMillan discovered that Django would not timeout on arbitrary URLs
  when the application used URLFields. This could be exploited by a remote
  attacker to cause a denial of service via resource exhaustion.
  (CVE-2011-4137)

  Paul McMillan discovered that while Django would check the validity of a
  URL via a HEAD request, it would instead use a GET request for the target
  of a redirect. This could potentially be used to trigger arbitrary GET
  requests via a crafted Location header. (CVE-2011-4138)

  It was discovered that Django would sometimes use a request's HTTP Host
  header to construct a full URL. A remote attacker could exploit this to
  conduct host header cache poisoning attacks via a crafted request.
  (CVE-2011-4139)");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-1ubuntu0.2.10.10.3", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.1.1-2ubuntu1.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.2.5-1ubuntu1.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
