###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for php5 USN-2658-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842265");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-07-07 06:44:17 +0200 (Tue, 07 Jul 2015)");
  script_cve_id("CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4025", "CVE-2015-4026",
                "CVE-2015-4598", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4643",
                "CVE-2015-4024", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4599",
                "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603",
                "CVE-2015-4604", "CVE-2015-4605", "CVE-2015-4644");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for php5 USN-2658-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Neal Poole and Tomas Hoger discovered that
PHP incorrectly handled NULL bytes in file paths. A remote attacker could possibly
use this issue to bypass intended restrictions and create or obtain access to
sensitive files. (CVE-2015-3411, CVE-2015-3412, CVE-2015-4025, CVE-2015-4026,
CVE-2015-4598)

Emmanuel Law discovered that the PHP phar extension incorrectly handled
filenames starting with a NULL byte. A remote attacker could use this issue
with a crafted tar archive to cause a denial of service. (CVE-2015-4021)

Max Spelsberg discovered that PHP incorrectly handled the LIST command
when connecting to remote FTP servers. A malicious FTP server could
possibly use this issue to execute arbitrary code. (CVE-2015-4022,
CVE-2015-4643)

Shusheng Liu discovered that PHP incorrectly handled certain malformed form
data. A remote attacker could use this issue with crafted form data to
cause CPU consumption, leading to a denial of service. (CVE-2015-4024)

Andrea Palazzo discovered that the PHP Soap client incorrectly validated
data types. A remote attacker could use this issue with crafted serialized
data to possibly execute arbitrary code. (CVE-2015-4147)

Andrea Palazzo discovered that the PHP Soap client incorrectly validated
that the uri property is a string. A remote attacker could use this issue
with crafted serialized data to possibly obtain sensitive information.
(CVE-2015-4148)

Taoguang Chen discovered that PHP incorrectly validated data types in
multiple locations. A remote attacker could possibly use these issues to
obtain sensitive information or cause a denial of service. (CVE-2015-4599,
CVE-2015-4600, CVE-2015-4601, CVE-2015-4602, CVE-2015-4603)

It was discovered that the PHP Fileinfo component incorrectly handled
certain files. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service. This issue only affected Ubuntu
15.04. (CVE-2015-4604, CVE-2015-4605)

It was discovered that PHP incorrectly handled table names in
php_pgsql_meta_data. A local attacker could possibly use this issue to
cause PHP to crash, resulting in a denial of service. (CVE-2015-4644)");
  script_tag(name:"affected", value:"php5 on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2658-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.10|14\.04 LTS|12\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.10")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.12+dfsg-2ubuntu4.6", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.12+dfsg-2ubuntu4.6", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.12+dfsg-2ubuntu4.6", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.12+dfsg-2ubuntu4.6", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.9+dfsg-1ubuntu4.11", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.9+dfsg-1ubuntu4.11", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.9+dfsg-1ubuntu4.11", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.9+dfsg-1ubuntu4.11", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.10-1ubuntu3.19", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.10-1ubuntu3.19", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.10-1ubuntu3.19", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.3.10-1ubuntu3.19", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
