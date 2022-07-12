###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1951_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for firefox USN-1951-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841553");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-09-18 10:13:03 +0530 (Wed, 18 Sep 2013)");
  script_cve_id("CVE-2013-1718", "CVE-2013-1719", "CVE-2013-1720", "CVE-2013-1721",
                "CVE-2013-1722", "CVE-2013-1724", "CVE-2013-1725", "CVE-2013-1728",
                "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736",
                "CVE-2013-1737", "CVE-2013-1738");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-1951-1");

  script_tag(name:"affected", value:"firefox on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted page, an attacker could possibly
exploit these to cause a denial of service via application crash, or
potentially execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2013-1718, CVE-2013-1719)

Atte Kettunen discovered a flaw in the HTML5 Tree Builder when interacting
with template elements. In some circumstances, an attacker could
potentially exploit this to execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2013-1720)

Alex Chapman discovered an integer overflow vulnerability in the ANGLE
library. An attacker could potentially exploit this to execute arbitrary
code with the privileges of the user invoking Firefox. (CVE-2013-1721)

Abhishek Arya discovered a use-after-free in the Animation Manager. An
attacked could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-1722)

Scott Bell discovered a use-after-free when using a select element. An
attacker could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-1724)

It was discovered that the scope of new Javascript objects could be
accessed before their compartment is initialized. An attacker could
potentially exploit this to execute code with the privileges of the user
invoking Firefox. (CVE-2013-1725)

Dan Gohman discovered that some variables and data were used in IonMonkey,
without being initialized, which could lead to information leakage.
(CVE-2013-1728)

Sachin Shinde discovered a crash when moving some XBL-backed nodes
in to a document created by document.open(). An attacker could potentially
exploit this to cause a denial of service. (CVE-2013-1730)

Aki Helin discovered a buffer overflow when combining lists, floats and
multiple columns. An attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-1732)

Two memory corruption bugs when scrolling were discovered. An attacker
could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2013-1735, CVE-2013-1736)

Boris Zbarsky discovered that user-defined getters on DOM proxies would
use the expando object as 'this'. An attacker could potentially exploit
this by tricking add-on code in to making incorrect security sensitive
decisions based on malicious values. (CVE-2013-1737)

A use-after-free bug was discovered in Firefox. An attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2013-1738)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1951-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"24.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"24.0+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"24.0+build1-0ubuntu0.13.04.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
