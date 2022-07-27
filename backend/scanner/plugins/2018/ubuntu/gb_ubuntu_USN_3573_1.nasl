###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3573_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for quagga USN-3573-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843451");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-16 08:25:08 +0100 (Fri, 16 Feb 2018)");
  script_cve_id("CVE-2018-5379", "CVE-2018-5378", "CVE-2018-5380", "CVE-2018-5381");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for quagga USN-3573-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that a double-free
vulnerability existed in the Quagga BGP daemon when processing certain forms
of UPDATE message. A remote attacker could use this to cause a denial of service
or possibly execute arbitrary code. (CVE-2018-5379)

It was discovered that the Quagga BGP daemon did not properly bounds
check the data sent with a NOTIFY to a peer. An attacker could use this
to expose sensitive information or possibly cause a denial of service.
This issue only affected Ubuntu 17.10. (CVE-2018-5378)

It was discovered that a table overrun vulnerability existed in the
Quagga BGP daemon. An attacker in control of a configured peer could
use this to possibly expose sensitive information or possibly cause
a denial of service. (CVE-2018-5380)

It was discovered that the Quagga BGP daemon in some configurations
did not properly handle invalid OPEN messages. An attacker in control
of a configured peer could use this to cause a denial of service
(infinite loop). (CVE-2018-5381)");
  script_tag(name:"affected", value:"quagga on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.ubuntu.com/usn/usn-3573-1");
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

  if ((res = isdpkgvuln(pkg:"quagga", ver:"0.99.22.4-3ubuntu1.5", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"quagga", ver:"1.1.1-3ubuntu0.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"quagga-bgpd", ver:"1.1.1-3ubuntu0.2", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"quagga", ver:"0.99.24.1-2ubuntu1.4", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
