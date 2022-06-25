###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3665_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for tomcat8 USN-3665-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843539");
  script_version("$Revision: 14288 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-06-05 14:03:23 +0530 (Tue, 05 Jun 2018)");
  script_cve_id("CVE-2017-12616", "CVE-2017-12617", "CVE-2017-15706", "CVE-2018-1304",
                "CVE-2018-1305", "CVE-2018-8014");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for tomcat8 USN-3665-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat8'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly
handled being configured with HTTP PUTs enabled. A remote attacker could use
this issue to upload a JSP file to the server and execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 17.10.
(CVE-2017-12616, CVE-2017-12617)

It was discovered that Tomcat contained incorrect documentation regarding
description of the search algorithm used by the CGI Servlet to identify
which script to execute. This issue only affected Ubuntu 17.10.
(CVE-2017-15706)

It was discovered that Tomcat incorrectly handled en empty string URL
pattern in security constraint definitions. A remote attacker could
possibly use this issue to gain access to web application resources,
contrary to expectations. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2018-1304)

It was discovered that Tomcat incorrectly handled applying certain security
constraints. A remote attacker could possibly access certain resources,
contrary to expectations. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2018-1305)

It was discovered that the Tomcat CORS filter default settings were
insecure and would enable 'supportsCredentials' for all origins, contrary
to expectations. (CVE-2018-8014)");
  script_tag(name:"affected", value:"tomcat8 on Ubuntu 18.04 LTS,
  Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3665-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.10|18\.04 LTS|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.52-1ubuntu0.14", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tomcat7", ver:"7.0.52-1ubuntu0.14", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.5.21-1ubuntu1.1", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tomcat8", ver:"8.5.21-1ubuntu1.1", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.5.30-1ubuntu1.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tomcat8", ver:"8.5.30-1ubuntu1.2", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.0.32-1ubuntu1.6", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tomcat8", ver:"8.0.32-1ubuntu1.6", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
