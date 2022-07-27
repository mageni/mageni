###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for oxygen-gtk3 USN-2936-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.842728");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-06 15:29:29 +0530 (Fri, 06 May 2016)");
  script_cve_id("CVE-2016-2804", "CVE-2016-2806", "CVE-2016-2807", "CVE-2016-2808",
		"CVE-2016-2811", "CVE-2016-2812", "CVE-2016-2814", "CVE-2016-2816",
		"CVE-2016-2817", "CVE-2016-2820");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for oxygen-gtk3 USN-2936-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxygen-gtk3'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-2936-1 fixed vulnerabilities in Firefox.
  The update caused Firefox to crash on startup with the Oxygen GTK theme due to
  a pre-existing bug in the Oxygen-GTK3 theme engine. This update fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  Christian Holler, Tyson Smith, Phil Ringalda, Gary Kwong, Jesse Ruderman,
  Mats Palmgren, Carsten Book, Boris Zbarsky, David Bolter, Randell Jesup,
  Andrew McCreight, and Steve Fink discovered multiple memory safety issues
  in Firefox. If a user were tricked in to opening a specially crafted
  website, an attacker could potentially exploit these to cause a denial of
  service via application crash, or execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2016-2804, CVE-2016-2806,
  CVE-2016-2807)

  An invalid write was discovered when using the JavaScript .watch() method in
  some circumstances. If a user were tricked in to opening a specially crafted
  website, an attacker could potentially exploit this to cause a denial of
  service via application crash, or execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2016-2808)

  Looben Yang discovered a use-after-free and buffer overflow in service
  workers. If a user were tricked in to opening a specially crafted website,
  an attacker could potentially exploit these to cause a denial of service
  via application crash, or execute arbitrary code with the privileges of
  the user invoking Firefox. (CVE-2016-2811, CVE-2016-2812)

  Sascha Just discovered a buffer overflow in libstagefright in some
  circumstances. If a user were tricked in to opening a specially crafted
  website, an attacker could potentially exploit this to cause a denial of
  service via application crash, or execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2016-2814)

  Muneaki Nishimura discovered that CSP is not applied correctly to web
  content sent with the multipart/x-mixed-replace MIME type. An attacker
  could potentially exploit this to conduct cross-site scripting (XSS)
  attacks when they would otherwise be prevented. (CVE-2016-2816)

  Muneaki Nishimura discovered that the chrome.tabs.update API for web
  extensions allows for navigation to javascript: URLs. A malicious
  extension could potentially exploit this to conduct cross-site scripting
  (XSS) attacks. (CVE-2016-2817)

  Mark Goodwin discovered that about:healthreport accepts certain events
  from any content present in the remote-report iframe. If another
  vulnerability allowed the injection of web content in the remote-report
  iframe, an attacker could potentially exploit this to change the user's
  sharing preferences. (CVE-2016-2820)");
  script_tag(name:"affected", value:"oxygen-gtk3 on Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2936-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04 LTS");

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

  if ((res = isdpkgvuln(pkg:"gtk3-engines-oxygen:i386", ver:"1.0.2-0ubuntu3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"gtk3-engines-oxygen:amd64", ver:"1.0.2-0ubuntu3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}