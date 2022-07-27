###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1079.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1079-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.891079");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2015-3152", "CVE-2017-10788", "CVE-2017-10789");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1079-1] libdbd-mysql-perl security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/08/msg00033.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"libdbd-mysql-perl on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
4.021-1+deb7u3.

We recommend that you upgrade your libdbd-mysql-perl packages.");
  script_tag(name:"summary", value:"The Perl library for communicating with MySQL database, used in the
'mysql' commandline client is vulnerable to a man in the middle attack
in SSL configurations and remote crash when connecting to hostile
servers.

CVE-2017-10788

The DBD::mysql module through 4.042 for Perl allows remote
attackers to cause a denial of service (use-after-free and
application crash) or possibly have unspecified other impact by
triggering (1) certain error responses from a MySQL server or (2)
a loss of a network connection to a MySQL server. The
use-after-free defect was introduced by relying on incorrect
Oracle mysql_stmt_close documentation and code examples.

CVE-2017-10789

The DBD::mysql module through 4.042 for Perl uses the mysql_ssl=1
setting to mean that SSL is optional (even though this setting's
documentation has a 'your communication with the server will be
encrypted' statement), which allows man-in-the-middle attackers to
spoof servers via a cleartext-downgrade attack, a related issue to
CVE-2015-3152.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libdbd-mysql-perl", ver:"4.021-1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}