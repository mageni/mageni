###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for php5 USN-2952-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842720");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-06 15:29:08 +0530 (Fri, 06 May 2016)");
  script_cve_id("CVE-2014-9767", "CVE-2015-8835", "CVE-2016-3185", "CVE-2015-8838",
		"CVE-2016-1903", "CVE-2016-2554", "CVE-2016-3141", "CVE-2016-3142");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for php5 USN-2952-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that the PHP Zip
  extension incorrectly handled directories when processing certain zip files.
  A remote attacker could possibly use this issue to create arbitrary directories.
  (CVE-2014-9767)

  It was discovered that the PHP Soap client incorrectly validated data
  types. A remote attacker could use this issue to cause PHP to crash,
  resulting in a denial of service, or possibly execute arbitrary code.
  (CVE-2015-8835, CVE-2016-3185)

  It was discovered that the PHP MySQL native driver incorrectly handled TLS
  connections to MySQL databases. A man in the middle attacker could possibly
  use this issue to downgrade and snoop on TLS connections. This
  vulnerability is known as BACKRONYM. (CVE-2015-8838)

  It was discovered that PHP incorrectly handled the imagerotate function. A
  remote attacker could use this issue to cause PHP to crash, resulting in a
  denial of service, or possibly obtain sensitive information. This issue
  only applied to Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2016-1903)

  Hans Jerry Illikainen discovered that the PHP phar extension incorrectly
  handled certain tar archives. A remote attacker could use this issue to
  cause PHP to crash, resulting in a denial of service, or possibly execute
  arbitrary code. (CVE-2016-2554)

  It was discovered that the PHP WDDX extension incorrectly handled certain
  malformed XML data. A remote attacker could possibly use this issue to
  cause PHP to crash, resulting in a denial of service, or possibly execute
  arbitrary code. (CVE-2016-3141)

  It was discovered that the PHP phar extension incorrectly handled certain
  zip files. A remote attacker could use this issue to cause PHP to crash,
  resulting in a denial of service, or possibly obtain sensitive information.
  (CVE-2016-3142)

  It was discovered that the PHP libxml_disable_entity_loader() setting was
  shared between threads. When running under PHP-FPM, this could result in
  XML external entity injection and entity expansion issues. This issue only
  applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (No CVE number)

  It was discovered that the PHP openssl_random_pseudo_bytes() function did
  not return cryptographically strong pseudo-random bytes. (No CVE number)

  It was discovered that the PHP Fileinfo component incorrectly handled
  certain magic files. An attacker could use this issue to cause PHP to
  crash, resulting in a denial of service, or possibly execute arbitrary
  code. (CVE number pending)

  It was discovered that the PHP php_snmp_error() function incorrectly
  handled string formatting. A remote attacker could use this issue to cause
  PHP to crash, resulting in  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"php5 on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2952-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|15\.10)");

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

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
