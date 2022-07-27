###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2209_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for libvirt USN-2209-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841804");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-05-12 09:12:52 +0530 (Mon, 12 May 2014)");
  script_cve_id("CVE-2013-6456", "CVE-2013-7336");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:N/I:P/A:C");
  script_name("Ubuntu Update for libvirt USN-2209-1");

  script_tag(name:"affected", value:"libvirt on Ubuntu 13.10");
  script_tag(name:"insight", value:"It was discovered that libvirt incorrectly handled symlinks
when using the LXC driver. An attacker could possibly use this issue to delete
host devices, create arbitrary nodes, and shutdown or power off the host.
(CVE-2013-6456)

Marian Krcmarik discovered that libvirt incorrectly handled seamless SPICE
migrations. An attacker could possibly use this issue to cause a denial of
service. (CVE-2013-7336)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2209-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.10");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"libvirt-bin", ver:"1.1.1-0ubuntu8.11", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libvirt0", ver:"1.1.1-0ubuntu8.11", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
