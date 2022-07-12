###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for tomcat7 USN-3024-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842823");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2016-07-06 05:25:52 +0200 (Wed, 06 Jul 2016)");
  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351",
        	"CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763", "CVE-2016-3092");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for tomcat7 USN-3024-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat7'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly
  handled pathnames used by web applications in a getResource, getResourceAsStream,
  or getResourcePaths call. A remote attacker could use this issue to possibly list
  a parent directory . This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS
  and Ubuntu 15.10. (CVE-2015-5174)

It was discovered that the Tomcat mapper component incorrectly handled
redirects. A remote attacker could use this issue to determine the
existence of a directory. This issue only affected Ubuntu 12.04 LTS,
Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-5345)

It was discovered that Tomcat incorrectly handled different session
settings when multiple versions of the same web application was deployed. A
remote attacker could possibly use this issue to hijack web sessions. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-5346)

It was discovered that the Tomcat Manager and Host Manager applications
incorrectly handled new requests. A remote attacker could possibly use this
issue to bypass CSRF protection mechanisms. This issue only affected Ubuntu
14.04 LTS and Ubuntu 15.10. (CVE-2015-5351)

It was discovered that Tomcat did not place StatusManagerServlet on the
RestrictedServlets list. A remote attacker could possibly use this issue to
read arbitrary HTTP requests, including session ID values. This issue only
affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.10.
(CVE-2016-0706)

It was discovered that the Tomcat session-persistence implementation
incorrectly handled session attributes. A remote attacker could possibly
use this issue to execute arbitrary code in a privileged context. This
issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.10.
(CVE-2016-0714)

It was discovered that the Tomcat setGlobalContext method incorrectly
checked if callers were authorized. A remote attacker could possibly use
this issue to read or write to arbitrary application data, or cause a denial
of service. This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and
Ubuntu 15.10. (CVE-2016-0763)

It was discovered that the Tomcat Fileupload library incorrectly handled
certain upload requests. A remote attacker could possibly use this issue to
cause a denial of service. (CVE-2016-3092)");
  script_tag(name:"affected", value:"tomcat7 on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3024-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|16\.04 LTS|15\.10)");

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

  if ((res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.52-1ubuntu0.6", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.35-1ubuntu3.7", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.68-1ubuntu0.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.64-1ubuntu0.3", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
