###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for ubufox USN-2743-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842457");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-09-24 07:27:37 +0200 (Thu, 24 Sep 2015)");
  script_cve_id("CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4502", "CVE-2015-4504", "CVE-2015-4506", "CVE-2015-4507", "CVE-2015-4508", "CVE-2015-4509", "CVE-2015-4510", "CVE-2015-4512", "CVE-2015-4516", "CVE-2015-4517", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180", "CVE-2015-4519", "CVE-2015-4520");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for ubufox USN-2743-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ubufox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-2743-1 fixed vulnerabilities in Firefox. This update provides the
corresponding update for Ubufox.

Original advisory details:

Andrew Osmond, Olli Pettay, Andrew Sutherland, Christian Holler, David
Major, Andrew McCreight, Cameron McCormack, Bob Clary and Randell Jesup
discovered multiple memory safety issues in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-4500, CVE-2015-4501)

Andr&#233  Bargull discovered that when a web page creates a scripted proxy
for the window with a handler defined a certain way, a reference to the
inner window will be passed, rather than that of the outer window.
(CVE-2015-4502)

Felix Gr&#246 bert discovered an out-of-bounds read in the QCMS color
management library in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via application crash, or obtain
sensitive information. (CVE-2015-4504)

Khalil Zhani discovered a buffer overflow when parsing VP9 content in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-4506)

Spandan Veggalam discovered a crash while using the debugger API in some
circumstances. If a user were tricked in to opening a specially crafted
website whilst using the debugger, an attacker could potentially exploit
this to execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-4507)

Juho Nurminen discovered that the URL bar could display the wrong URL in
reader mode in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
conduct URL spoofing attacks. (CVE-2015-4508)

A use-after-free was discovered when manipulating HTML media content in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2015-4509)

Looben Yang discovered a use-after-free when using a shared worker with
IndexedDB in some circumstances. If a user were tricked in to opening a
specially crafted website, a ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ubufox on Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2743-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(15\.04|14\.04 LTS|12\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU15.04")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"3.2-0ubuntu0.15.04.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"3.2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"3.2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}