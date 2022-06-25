###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1400_3.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for thunderbird USN-1400-3
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1400-3/");
  script_oid("1.3.6.1.4.1.25623.1.0.840958");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-03-22 10:45:44 +0530 (Thu, 22 Mar 2012)");
  script_cve_id("CVE-2012-0455", "CVE-2012-0457", "CVE-2012-0456", "CVE-2012-0451",
                "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461",
                "CVE-2012-0462", "CVE-2012-0464");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for thunderbird USN-1400-3");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.10");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1400-3");
  script_tag(name:"affected", value:"thunderbird on Ubuntu 11.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1400-1 fixed vulnerabilities in Firefox. This update provides the
  corresponding fixes for Thunderbird.

  Original advisory details:

  Soroush Dalili discovered that Firefox did not adequately protect against
  dropping JavaScript links onto a frame. A remote attacker could, through
  cross-site scripting (XSS), exploit this to modify the contents or steal
  confidential data. (CVE-2012-0455)

  Atte Kettunen discovered a use-after-free vulnerability in Firefox's
  handling of SVG animations. An attacker could potentially exploit this to
  execute arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2012-0457)

  Atte Kettunen discovered an out of bounds read vulnerability in Firefox's
  handling of SVG Filters. An attacker could potentially exploit this to make
  data from the user's memory accessible to the page content. (CVE-2012-0456)

  Mike Brooks discovered that using carriage return line feed (CRLF)
  injection, one could introduce a new Content Security Policy (CSP) rule
  which allows for cross-site scripting (XSS) on sites with a separate header
  injection vulnerability. With cross-site scripting vulnerabilities, if a
  user were tricked into viewing a specially crafted page, a remote attacker
  could exploit this to modify the contents, or steal confidential data,
  within the same domain. (CVE-2012-0451)

  Mariusz Mlynski discovered that the Home button accepted JavaScript links
  to set the browser Home page. An attacker could use this vulnerability to
  get the script URL loaded in the privileged about:sessionrestore context.
  (CVE-2012-0458)

  Daniel Glazman discovered that the Cascading Style Sheets (CSS)
  implementation is vulnerable to crashing due to modification of a keyframe
  followed by access to the cssText of the keyframe. If the user were tricked
  into opening a specially crafted web page, an attacker could exploit this
  to cause a denial of service via application crash, or potentially execute
  code with the privileges of the user invoking Firefox. (CVE-2012-0459)

  Matt Brubeck discovered that Firefox did not properly restrict access to
  the window.fullScreen object. If the user were tricked into opening a
  specially crafted web page, an attacker could potentially use this
  vulnerability to spoof the user interface. (CVE-2012-0460)

  Bob Clary, Christian Holler, Jesse Ruderman, Michael Bebenita, David
  Anderson, Jeff Walden, Vincenzo Iozzo, and Willem Pinckaers discovered
  memory safety issues affecting Firefox. If the user were tricked into
  opening a specially crafted page, an attacker could exploit these to
  cause a denial of service via application crash, or potentially execute
  code with the privileges of the user invoking Firefox. (CVE-2012-0461,
  CVE-2012-0462, CVE-2012-0464)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"11.0+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
