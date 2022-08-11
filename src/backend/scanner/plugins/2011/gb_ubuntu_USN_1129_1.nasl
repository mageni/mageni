###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1129_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for perl USN-1129-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1129-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840647");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1168", "CVE-2010-1447", "CVE-2010-2761", "CVE-2010-4411", "CVE-2010-4410", "CVE-2011-1487");
  script_name("Ubuntu Update for perl USN-1129-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|6\.06 LTS|8\.04 LTS|11\.04|10\.10)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1129-1");
  script_tag(name:"affected", value:"perl on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS,
  Ubuntu 6.06 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that the Safe.pm Perl module incorrectly handled
  Safe::reval and Safe::rdo access restrictions. An attacker could use this
  flaw to bypass intended restrictions and possibly execute arbitrary code.
  (CVE-2010-1168, CVE-2010-1447)

  It was discovered that the CGI.pm Perl module incorrectly handled certain
  MIME boundary strings. An attacker could use this flaw to inject arbitrary
  HTTP headers and perform HTTP response splitting and cross-site scripting
  attacks. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 10.04 LTS and
  10.10. (CVE-2010-2761, CVE-2010-4411)

  It was discovered that the CGI.pm Perl module incorrectly handled newline
  characters. An attacker could use this flaw to inject arbitrary HTTP
  headers and perform HTTP response splitting and cross-site scripting
  attacks. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 10.04 LTS and
  10.10. (CVE-2010-4410)

  It was discovered that the lc, lcfirst, uc, and ucfirst functions did not
  properly apply the taint attribute when processing tainted input. An
  attacker could use this flaw to bypass intended restrictions. This issue
  only affected Ubuntu 8.04 LTS, 10.04 LTS and 10.10. (CVE-2011-1487)");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"perl", ver:"5.10.1-8ubuntu2.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"perl", ver:"5.8.7-10ubuntu1.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"perl", ver:"5.8.8-12ubuntu0.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"perl", ver:"5.10.1-17ubuntu4.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"perl", ver:"5.10.1-12ubuntu2.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
