###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for samba USN-2855-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842644");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-02-17 06:27:45 +0100 (Wed, 17 Feb 2016)");
  script_cve_id("CVE-2015-5252", "CVE-2015-3223", "CVE-2015-5296", "CVE-2015-5299",
                "CVE-2015-5330", "CVE-2015-7540", "CVE-2015-8467");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for samba USN-2855-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-2855-1 fixed vulnerabilities in Samba.
  The upstream fix for CVE-2015-5252 introduced a regression in certain specific
  environments.This update fixes the problem.
  Original advisory details:

  Thilo Uttendorfer discovered that the Samba LDAP server incorrectly handled
  certain packets. A remote attacker could use this issue to cause the LDAP
  server to stop responding, resulting in a denial of service. This issue
  only affected Ubuntu 14.04 LTS, Ubuntu 15.04 and Ubuntu 15.10.
  (CVE-2015-3223)
  Jan Kasprzak discovered that Samba incorrectly handled certain symlinks. A
  remote attacker could use this issue to access files outside the exported
  share path. (CVE-2015-5252)
  Stefan Metzmacher discovered that Samba did not enforce signing when
  creating encrypted connections. If a remote attacker were able to perform a
  man-in-the-middle attack, this flaw could be exploited to view sensitive
  information. (CVE-2015-5296)
  It was discovered that Samba incorrectly performed access control when
  using the VFS shadow_copy2 module. A remote attacker could use this issue
  to access snapshots, contrary to intended permissions. (CVE-2015-5299)
  Douglas Bagnall discovered that Samba incorrectly handled certain string
  lengths. A remote attacker could use this issue to possibly access
  sensitive information. (CVE-2015-5330)
  It was discovered that the Samba LDAP server incorrectly handled certain
  packets. A remote attacker could use this issue to cause the LDAP server to
  stop responding, resulting in a denial of service. This issue only affected
  Ubuntu 14.04 LTS, Ubuntu 15.04 and Ubuntu 15.10. (CVE-2015-7540)
  Andrew Bartlett discovered that Samba incorrectly checked administrative
  privileges during creation of machine accounts. A remote attacker could
  possibly use this issue to bypass intended access restrictions in certain
  environments. This issue only affected Ubuntu 14.04 LTS, Ubuntu 15.04 and
  Ubuntu 15.10. (CVE-2015-8467)");
  script_tag(name:"affected", value:"samba on Ubuntu 15.10,

  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2855-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|15\.10)");

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

  if ((res = isdpkgvuln(pkg:"samba", ver:"2:4.1.6+dfsg-1ubuntu2.14.04.12", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"samba", ver:"2:3.6.3-2ubuntu2.14", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"samba", ver:"2:4.1.17+dfsg-4ubuntu3.2", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
