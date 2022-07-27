###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1757_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for python-django USN-1757-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1757-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841353");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-08 10:23:37 +0530 (Fri, 08 Mar 2013)");
  script_cve_id("CVE-2012-4520", "CVE-2013-0305", "CVE-2013-0306", "CVE-2013-1664",
                "CVE-2013-1665");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Ubuntu Update for python-django USN-1757-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|11\.10|10\.04 LTS|12\.10)");
  script_tag(name:"affected", value:"python-django on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"James Kettle discovered that Django did not properly filter the Host HTTP
  header when processing certain requests. An attacker could exploit this to
  generate and display arbitrary URLs to users. Although this issue had been
  previously addressed in USN-1632-1, this update adds additional hardening
  measures to host header validation. This update also adds a new
  ALLOWED_HOSTS setting that can be set to a list of acceptable values for
  headers. (CVE-2012-4520)

  Orange Tsai discovered that Django incorrectly performed permission checks
  when displaying the history view in the admin interface. An administrator
  could use this flaw to view the history of any object, regardless of
  intended permissions. (CVE-2013-0305)

  It was discovered that Django incorrectly handled a large number of forms
  when generating formsets. An attacker could use this flaw to cause Django
  to consume memory, resulting in a denial of service. (CVE-2013-0306)

  It was discovered that Django incorrectly deserialized XML. An attacker
  could use this flaw to perform entity-expansion and external-entity/DTD
  attacks. This updated modified Django behaviour to no longer allow DTDs,
  perform entity expansion, or fetch external entities/DTDs. (CVE-2013-1664,
  CVE-2013-1665)");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.3.1-4ubuntu1.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.3-2ubuntu1.6", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.1.1-2ubuntu1.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.4.1-2ubuntu0.3", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
