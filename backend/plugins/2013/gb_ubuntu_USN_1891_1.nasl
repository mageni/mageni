###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1891_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for thunderbird USN-1891-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841489");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-06-27 10:01:25 +0530 (Thu, 27 Jun 2013)");
  script_cve_id("CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686",
                "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693",
                "CVE-2013-1694", "CVE-2013-1697");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for thunderbird USN-1891-1");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1891-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|12\.10|13\.04)");
  script_tag(name:"affected", value:"thunderbird on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Thunderbird. If the user
  were tricked into opening a specially crafted message with scripting
  enabled, an attacker could possibly exploit these to cause a denial of
  service via application crash, or potentially execute arbitrary code with
  the privileges of the user invoking Thunderbird. (CVE-2013-1682)

  Abhishek Arya discovered multiple use-after-free bugs. If the user were
  tricked into opening a specially crafted message with scripting enabled,
  an attacker could possibly exploit these to execute arbitrary code with
  the privileges of the user invoking Thunderbird. (CVE-2013-1684,
  CVE-2013-1685, CVE-2013-1686)

  Mariusz Mlynski discovered that user defined code within the XBL scope of
  an element could be made to bypass System Only Wrappers (SOW). If a user
  had scripting enabled, an attacker could potentially exploit this to
  execute arbitrary code with the privileges of the user invoking
  Thunderbird. (CVE-2013-1687)

  A crash was discovered when reloading a page that contained content using
  the onreadystatechange event. If a user had scripting enabled, an attacker
  could potentially exploit this to execute arbitrary code with the
  privileges of the user invoking Thunderbird. (CVE-2013-1690)

  Johnathan Kuskos discovered that Thunderbird sent data in the body of
  XMLHttpRequest HEAD requests. If a user had scripting enabled, an attacker
  could exploit this to conduct Cross-Site Request Forgery (CSRF) attacks.
  (CVE-2013-1692)

  Paul Stone discovered a timing flaw in the processing of SVG images with
  filters. If a user had scripting enabled, an attacker could exploit this
  to view sensitive information. (CVE-2013-1693)

  Boris Zbarsky discovered a flaw in PreserveWrapper. If a user had
  scripting enabled, an attacker could potentially exploit this to cause
  a denial of service via application crash, or execute code with the
  privileges of the user invoking Thunderbird. (CVE-2013-1694)

  It was discovered that XrayWrappers could be bypassed to call
  content-defined methods in certain circumstances. If a user had scripting
  enabled, an attacker could exploit this to cause undefined behaviour.
  (CVE-2013-1697)");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.7+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.7+build1-0ubuntu0.12.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.7+build1-0ubuntu0.13.0", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
