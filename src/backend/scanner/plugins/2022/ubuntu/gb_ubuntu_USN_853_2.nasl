# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2009.853.2");
  script_cve_id("CVE-2009-1563", "CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3371", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T08:45:11+0000");
  script_tag(name:"last_modification", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-853-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU9\.10");

  script_xref(name:"Advisory-ID", value:"USN-853-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-853-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/480740");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox-3.5, xulrunner-1.9.1' package(s) announced via the USN-853-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-853-1 fixed vulnerabilities in Firefox and Xulrunner. The upstream
changes introduced regressions that could lead to crashes when processing
certain malformed GIF images, fonts and web pages. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 Alin Rad Pop discovered a heap-based buffer overflow in Firefox when it
 converted strings to floating point numbers. If a user were tricked into
 viewing a malicious website, a remote attacker could cause a denial of service
 or possibly execute arbitrary code with the privileges of the user invoking the
 program. (CVE-2009-1563)

 Jeremy Brown discovered that the Firefox Download Manager was vulnerable to
 symlink attacks. A local attacker could exploit this to create or overwrite
 files with the privileges of the user invoking the program. (CVE-2009-3274)

 Paul Stone discovered a flaw in the Firefox form history. If a user were
 tricked into viewing a malicious website, a remote attacker could access this
 data to steal confidential information. (CVE-2009-3370)

 Orlando Berrera discovered that Firefox did not properly free memory when using
 web-workers. If a user were tricked into viewing a malicious website, a remote
 attacker could cause a denial of service or possibly execute arbitrary code
 with the privileges of the user invoking the program. This issue only
 affected Ubuntu 9.10. (CVE-2009-3371)

 A flaw was discovered in the way Firefox processed Proxy Auto-configuration
 (PAC) files. If a user configured the browser to use PAC files with certain
 regular expressions, an attacker could cause a denial of service or possibly
 execute arbitrary code with the privileges of the user invoking the program.
 (CVE-2009-3372)

 A heap-based buffer overflow was discovered in Mozilla's GIF image parser. If a
 user were tricked into viewing a malicious website, a remote attacker could
 cause a denial of service or possibly execute arbitrary code with the
 privileges of the user invoking the program. (CVE-2009-3373)

 A flaw was discovered in the JavaScript engine of Firefox. An attacker could
 exploit this to execute scripts from page content with chrome privileges.
 (CVE-2009-3374)

 Gregory Fleischer discovered that the same-origin check in Firefox could be
 bypassed by utilizing the document.getSelection function. An attacker could
 exploit this to read data from other domains. (CVE-2009-3375)

 Jesse Ruderman and Sid Stamm discovered that Firefox did not properly display
 filenames containing right-to-left (RTL) override characters. If a user were
 tricked into downloading a malicious file with a crafted filename, an attacker
 could exploit this to trick the user into opening a different file than the
 user expected. (CVE-2009-3376)

 Several flaws were discovered in third party media libraries. If a user were
 tricked into opening a crafted media file, a remote attacker could ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox-3.5, xulrunner-1.9.1' package(s) on Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.5", ver:"3.5.5+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.1", ver:"1.9.1.5+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
