###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2000_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for nova USN-2000-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841598");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-10-29 16:21:58 +0530 (Tue, 29 Oct 2013)");
  script_cve_id("CVE-2013-2256", "CVE-2013-4278", "CVE-2013-4179", "CVE-2013-4185", "CVE-2013-4261");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("Ubuntu Update for nova USN-2000-1");

  script_tag(name:"affected", value:"nova on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"It was discovered that Nova did not properly enforce the is_public property
when determining flavor access. An authenticated attacker could exploit
this to obtain sensitive information in private flavors. This issue only
affected Ubuntu 12.10 and 13.10. (CVE-2013-2256, CVE-2013-4278)

Grant Murphy discovered that Nova would allow XML entity processing. A
remote unauthenticated attacker could exploit this using the Nova API to
cause a denial of service via resource exhaustion. This issue only
affected Ubuntu 13.10. (CVE-2013-4179)

Vishvananda Ishaya discovered that Nova inefficiently handled network
security group updates when Nova was configured to use nova-network. An
authenticated attacker could exploit this to cause a denial of service.
(CVE-2013-4185)

Jaroslav Henner discovered that Nova did not properly handle certain inputs
to the instance console when Nova was configured to use Apache Qpid. An
authenticated attacker could exploit this to cause a denial of service on
the compute node running the instance. By default, Ubuntu uses RabbitMQ
instead of Qpid. (CVE-2013-4261)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2000-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'nova'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|12\.10|13\.04)");

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

  if ((res = isdpkgvuln(pkg:"python-nova", ver:"2012.1.3+stable-20130423-e52e6912-0ubuntu1.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"python-nova", ver:"2012.2.4-0ubuntu3.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"python-nova", ver:"1:2013.1.3-0ubuntu1.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}