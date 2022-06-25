###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2323_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for horizon USN-2323-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841943");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-08-22 05:57:29 +0200 (Fri, 22 Aug 2014)");
  script_cve_id("CVE-2014-3473", "CVE-2014-3474", "CVE-2014-3475", "CVE-2014-3594");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Ubuntu Update for horizon USN-2323-1");

  script_tag(name:"affected", value:"horizon on Ubuntu 14.04 LTS");
  script_tag(name:"insight", value:"Jason Hullinger discovered that OpenStack Horizon did not
properly perform input sanitization on Heat templates. If a user were tricked
into using a specially crafted Heat template, an attacker could conduct
cross-site scripting attacks. With cross-site scripting vulnerabilities, if a
user were tricked into viewing server output during a crafted server request, a
remote attacker could exploit this to modify the contents, or steal
confidential data, within the same domain. (CVE-2014-3473)

Craig Lorentzen discovered that OpenStack Horizon did not properly perform
input sanitization when creating networks. If a user were tricked into
launching an image using the crafted network name, an attacker could
conduct cross-site scripting attacks. (CVE-2014-3474)

Michael Xin discovered that OpenStack Horizon did not properly perform
input sanitization when adding users. If an admin user were tricked into
viewing the users page containing a crafted email address, an attacker
could conduct cross-site scripting attacks. (CVE-2014-3475)

Dennis Felsch and Mario Heiderich discovered that OpenStack Horizon did not
properly perform input sanitization when creating host aggregates. If an
admin user were tricked into viewing the Host Aggregates page containing a
crafted availability zone name, an attacker could conduct cross-site
scripting attacks. (CVE-2014-3594)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2323-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'horizon'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04 LTS");

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

  if ((res = isdpkgvuln(pkg:"openstack-dashboard", ver:"1:2014.1.2-0ubuntu1.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
