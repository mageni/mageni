###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2298_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for oxide-qt USN-2298-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841913");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-07-28 16:39:33 +0530 (Mon, 28 Jul 2014)");
  script_cve_id("CVE-2014-1730", "CVE-2014-1731", "CVE-2014-1735", "CVE-2014-3162",
                "CVE-2014-1740", "CVE-2014-1741", "CVE-2014-1742", "CVE-2014-1743",
                "CVE-2014-1744", "CVE-2014-1746", "CVE-2014-1748", "CVE-2014-3152",
                "CVE-2014-3154", "CVE-2014-3155", "CVE-2014-3157", "CVE-2014-3160",
                "CVE-2014-3803");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Ubuntu Update for oxide-qt USN-2298-1");

  script_tag(name:"affected", value:"oxide-qt on Ubuntu 14.04 LTS");
  script_tag(name:"insight", value:"A type confusion bug was discovered in V8. If a user were
tricked in to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or execute
arbitrary code with the privileges of the sandboxed render process.
(CVE-2014-1730)

A type confusion bug was discovered in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash, or execute arbitrary
code with the privileges of the sandboxed render process. (CVE-2014-1731)

Multiple security issues including memory safety bugs were discovered in
Chromium. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking the program. (CVE-2014-1735, CVE-2014-3162)

Multiple use-after-free issues were discovered in the WebSockets
implementation. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-1740)

Multiple integer overflows were discovered in CharacterData
implementation. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of
service via renderer crash or execute arbitrary code with the privileges
of the sandboxed render process. (CVE-2014-1741)

Multiple use-after-free issues were discovered in Blink. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via renderer crash
or execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-1742, CVE-2014-1743)

An integer overflow bug was discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
the program. (CVE-2014-1744)

An out-of-bounds read was discovered in Chromium. If a user were tricked
in to opening a specially crafter website, an attacker could potentially
exploit this to cause a denial of service via application crash.
(CVE-2014-1746)

It was discovered that Blink allowed scrollbar painting to extend in to
the parent frame in some circumstances. An attacker could potentially
exploit ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2298-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt'
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

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.0.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs:i386", ver:"1.0.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs-extra:i386", ver:"1.0.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
