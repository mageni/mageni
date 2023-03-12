# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.626");
  script_cve_id("CVE-2016-6606", "CVE-2016-6607", "CVE-2016-6609", "CVE-2016-6611", "CVE-2016-6612", "CVE-2016-6613", "CVE-2016-6614", "CVE-2016-6620", "CVE-2016-6622", "CVE-2016-6623", "CVE-2016-6624", "CVE-2016-6630", "CVE-2016-6631");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-08 01:29:00 +0000 (Sun, 08 Jul 2018)");

  script_name("Debian: Security Advisory (DLA-626)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-626");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-626");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DLA-626 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Phpmyadmin, a web administration tool for MySQL, had several vulnerabilities reported.

CVE-2016-6606

A pair of vulnerabilities were found affecting the way cookies are stored.

The decryption of the username/password is vulnerable to a padding oracle attack. The can allow an attacker who has access to a user's browser cookie file to decrypt the username and password.

A vulnerability was found where the same initialization vector is used to hash the username and password stored in the phpMyAdmin cookie. If a user has the same password as their username, an attacker who examines the browser cookie can see that they are the same -- but the attacker can not directly decode these values from the cookie as it is still hashed.

CVE-2016-6607

Cross site scripting vulnerability in the replication feature

CVE-2016-6609

A specially crafted database name could be used to run arbitrary PHP commands through the array export feature.

CVE-2016-6611

A specially crafted database and/or table name can be used to trigger an SQL injection attack through the SQL export functionality.

CVE-2016-6612

A user can exploit the LOAD LOCAL INFILE functionality to expose files on the server to the database system.

CVE-2016-6613

A user can specially craft a symlink on disk, to a file which phpMyAdmin is permitted to read but the user is not, which phpMyAdmin will then expose to the user.

CVE-2016-6614

A vulnerability was reported with the %u username replacement functionality of the SaveDir and UploadDir features. When the username substitution is configured, a specially-crafted user name can be used to circumvent restrictions to traverse the file system.

CVE-2016-6620

A vulnerability was reported where some data is passed to the PHP unserialize() function without verification that it's valid serialized data. Due to how the PHP function operates, unserialization can result in code being loaded and executed due to object instantiation and autoloading, and a malicious user may be able to exploit this. Therefore, a malicious user may be able to manipulate the stored data in a way to exploit this weakness.

CVE-2016-6622

An unauthenticated user is able to execute a denial-of-service attack by forcing persistent connections when phpMyAdmin is running with $cfg['AllowArbitraryServer']=true,.

CVE-2016-6623

A malicious authorized user can cause a denial-of-service attack on a server by passing large values to a loop.

CVE-2016-6624

A vulnerability was discovered where, under certain circumstances, it may be possible to circumvent the phpMyAdmin IP-based authentication rules. When phpMyAdmin is used with IPv6 in a proxy server environment, and the proxy server is in the allowed range but the attacking computer is not allowed, this vulnerability can allow the attacking computer to connect despite the IP rules.

CVE-2016-6630

An authenticated user can trigger a denial-of-service attack by ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:3.4.11.1-2+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
