###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2345_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for oxide-qt USN-2345-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842005");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-10-15 06:09:08 +0200 (Wed, 15 Oct 2014)");
  script_cve_id("CVE-2014-3178", "CVE-2014-3190", "CVE-2014-3191", "CVE-2014-3192",
                "CVE-2014-3179", "CVE-2014-3200", "CVE-2014-3188", "CVE-2014-3194",
                "CVE-2014-3195", "CVE-2014-3197", "CVE-2014-3199", "CVE-2014-7967");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for oxide-qt USN-2345-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple use-after-free issues were
discovered in Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of service
via renderer crash, or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2014-3178, CVE-2014-3190, CVE-2014-3191,
CVE-2014-3192)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-3179,
CVE-2014-3200)

It was discovered that Chromium did not properly handle the interaction of
IPC and V8. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to execute arbitrary
code with the privileges of the user invoking the program. (CVE-2014-3188)

A use-after-free was discovered in the web workers implementation in
Chromium. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the privileges of the
user invoking the program. (CVE-2014-3194)

It was discovered that V8 did not correctly handle Javascript heap
allocations in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
steal sensitive information. (CVE-2014-3195)

It was discovered that Blink did not properly provide substitute data for
pages blocked by the XSS auditor. If a user were tricked in to opening a
specially crafter website, an attacker could potentially exploit this to
steal sensitive information. (CVE-2014-3197)

It was discovered that the wrap function for Event's in the V8 bindings
in Blink produced an erroneous result in some circumstances. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service by stopping a worker
process that was handling an Event object. (CVE-2014-3199)

Multiple security issues were discovered in V8. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit these to read uninitialized memory, cause a denial of service via
renderer crash or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2014-7967)");
  script_tag(name:"affected", value:"oxide-qt on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2345-1/");
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

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.2.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:amd64", ver:"1.2.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs:i386", ver:"1.2.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs:amd64", ver:"1.2.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs-extra:i386", ver:"1.2.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs-extra:amd64", ver:"1.2.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
