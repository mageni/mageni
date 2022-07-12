###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for php7.0 USN-2984-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842772");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-25 05:20:47 +0200 (Wed, 25 May 2016)");
  script_cve_id("CVE-2015-8865", "CVE-2016-3078", "CVE-2016-3132", "CVE-2016-4070",
		"CVE-2016-4071", "CVE-2016-4072", "CVE-2016-4073", "CVE-2016-4342",
		"CVE-2016-4343", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539",
		"CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543",
		"CVE-2016-4544");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for php7.0 USN-2984-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.0'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that the PHP Fileinfo
  component incorrectly handled certain magic files. An attacker could use this
  issue to cause PHP to crash, resulting in a denial of service, or possibly
  execute arbitrary code. This issue only affected Ubuntu 16.04 LTS.
  (CVE-2015-8865)

  Hans Jerry Illikainen discovered that the PHP Zip extension incorrectly
  handled certain malformed Zip archives. A remote attacker could use this
  issue to cause PHP to crash, resulting in a denial of service, or possibly
  execute arbitrary code. This issue only affected Ubuntu 16.04 LTS.
  (CVE-2016-3078)

  It was discovered that PHP incorrectly handled invalid indexes in the
  SplDoublyLinkedList class. An attacker could use this issue to cause PHP to
  crash, resulting in a denial of service, or possibly execute arbitrary
  code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-3132)

  It was discovered that the PHP rawurlencode() function incorrectly handled
  large strings. A remote attacker could use this issue to cause PHP to
  crash, resulting in a denial of service. This issue only affected Ubuntu
  16.04 LTS. (CVE-2016-4070)

  It was discovered that the PHP php_snmp_error() function incorrectly
  handled string formatting. A remote attacker could use this issue to cause
  PHP to crash, resulting in a denial of service, or possibly execute
  arbitrary code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-4071)

  It was discovered that the PHP phar extension incorrectly handled certain
  filenames in archives. A remote attacker could use this issue to cause PHP
  to crash, resulting in a denial of service, or possibly execute arbitrary
  code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-4072)

  It was discovered that the PHP mb_strcut() function incorrectly handled
  string formatting. A remote attacker could use this issue to cause PHP to
  crash, resulting in a denial of service, or possibly execute arbitrary
  code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-4073)

  It was discovered that the PHP phar extension incorrectly handled certain
  archive files. A remote attacker could use this issue to cause PHP to
  crash, resulting in a denial of service, or possibly execute arbitrary
  code. This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and
  Ubuntu 15.10. (CVE-2016-4342, CVE-2016-4343)

  It was discovered that the PHP bcpowmod() function incorrectly handled
  memory. A remote attacker could use this issue to cause PHP to crash,
  resulting in a denial of service, or possibly execute arbitrary code.
  (CVE-2016-4537, CVE-2016-4538)

  It was discovered that the PHP XM ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"php7.0 on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2984-1/");
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

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.9+dfsg-1ubuntu4.17", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.9+dfsg-1ubuntu4.17", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.9+dfsg-1ubuntu4.17", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.9+dfsg-1ubuntu4.17", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.10-1ubuntu3.23", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.10-1ubuntu3.23", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.10-1ubuntu3.23", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.3.10-1ubuntu3.23", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php7.0", ver:"7.0.4-7ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php7.0-cgi", ver:"7.0.4-7ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php7.0-cli", ver:"7.0.4-7ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php7.0-fpm", ver:"7.0.4-7ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.6.11+dfsg-1ubuntu3.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.6.11+dfsg-1ubuntu3.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.6.11+dfsg-1ubuntu3.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.6.11+dfsg-1ubuntu3.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
