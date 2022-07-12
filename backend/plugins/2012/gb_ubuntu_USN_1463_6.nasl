###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1463_6.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for thunderbird USN-1463-6
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1463-6/");
  script_oid("1.3.6.1.4.1.25623.1.0.841059");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-28 10:37:07 +0530 (Thu, 28 Jun 2012)");
  script_cve_id("CVE-2012-1937", "CVE-2012-1938", "CVE-2011-3101", "CVE-2012-1944",
                "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-0441", "CVE-2012-1940",
                "CVE-2012-1941", "CVE-2012-1947");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for thunderbird USN-1463-6");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1463-6");
  script_tag(name:"affected", value:"thunderbird on Ubuntu 11.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1463-1 fixed vulnerabilities in Firefox. This update provides the
  corresponding fixes for Thunderbird.

  Original advisory details:

  Jesse Ruderman, Igor Bukanov, Bill McCloskey, Christian Holler, Andrew
  McCreight, Olli Pettay, Boris Zbarsky, and Brian Bondy discovered memory
  safety issues affecting Firefox. If the user were tricked into opening a
  specially crafted page, an attacker could possibly exploit these to cause a
  denial of service via application crash, or potentially execute code with
  the privileges of the user invoking Firefox. (CVE-2012-1937, CVE-2012-1938)

  It was discovered that Mozilla's WebGL implementation exposed a bug in
  certain NVIDIA graphics drivers. The impact of this issue has not been
  disclosed at this time. (CVE-2011-3101)

  Adam Barth discovered that certain inline event handlers were not being
  blocked properly by the Content Security Policy's (CSP) inline-script
  blocking feature. Web applications relying on this feature of CSP to
  protect against cross-site scripting (XSS) were not fully protected. With
  cross-site scripting vulnerabilities, if a user were tricked into viewing a
  specially crafted page, a remote attacker could exploit this to modify the
  contents, or steal confidential data, within the same domain.
  (CVE-2012-1944)

  Paul Stone discovered that a viewed HTML page hosted on a Windows or Samba
  share could load Windows shortcut files (.lnk) in the same share. These
  shortcut files could then link to arbitrary locations on the local file
  system of the individual loading the HTML page. An attacker could
  potentially use this vulnerability to show the contents of these linked
  files or directories in an iframe, resulting in information disclosure.
  (CVE-2012-1945)

  Arthur Gerkis discovered a use-after-free vulnerability while
  replacing/inserting a node in a document. If the user were tricked into
  opening a specially crafted page, an attacker could possibly exploit this
  to cause a denial of service via application crash, or potentially execute
  code with the privileges of the user invoking Firefox. (CVE-2012-1946)

  Kaspar Brand discovered a vulnerability in how the Network Security
  Services (NSS) ASN.1 decoder handles zero length items. If the user were
  tricked into opening a specially crafted page, an attacker could possibly
  exploit this to cause a denial of service via application crash.
  (CVE-2012-0441)

  Abhishek Arya discovered two buffer overflow and one use-after-free
  vulnerabilities. If the user were tricked into opening a specially crafted
  page, an attacker could ...

  Description truncated, please see the referenced URL(s) for more information.");
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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"13.0.1+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
