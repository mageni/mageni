###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1368_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for apache2 USN-1368-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1368-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840900");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-21 19:00:08 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2011-3607", "CVE-2011-4317", "CVE-2012-0021", "CVE-2012-0031", "CVE-2012-0053");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for apache2 USN-1368-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS|11\.04|8\.04 LTS)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1368-1");
  script_tag(name:"affected", value:"apache2 on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that the Apache HTTP Server incorrectly handled the
  SetEnvIf .htaccess file directive. An attacker having write access to a
  .htaccess file may exploit this to possibly execute arbitrary code.
  (CVE-2011-3607)

  Prutha Parikh discovered that the mod_proxy module did not properly
  interact with the RewriteRule and ProxyPassMatch pattern matches in the
  configuration of a reverse proxy. This could allow remote attackers to
  contact internal webservers behind the proxy that were not intended for
  external exposure. (CVE-2011-4317)

  Rainer Canavan discovered that the mod_log_config module incorrectly
  handled a certain format string when used with a threaded MPM. A remote
  attacker could exploit this to cause a denial of service via a specially-
  crafted cookie. This issue only affected Ubuntu 11.04 and 11.10.
  (CVE-2012-0021)

  It was discovered that the Apache HTTP Server incorrectly handled certain
  type fields within a scoreboard shared memory segment. A local attacker
  could exploit this to to cause a denial of service. (CVE-2012-0031)

  Norman Hippert discovered that the Apache HTTP Server incorrecly handled
  header information when returning a Bad Request (400) error page. A remote
  attacker could exploit this to obtain the values of certain HTTPOnly
  cookies. (CVE-2012-0053)");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.16-1ubuntu3.5", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.14-5ubuntu8.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.17-1ubuntu1.5", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.8-1ubuntu0.23", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
