###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1592.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1592-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891592");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-19141", "CVE-2018-19143");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1592-1] otrs2 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-11-26 00:00:00 +0100 (Mon, 26 Nov 2018)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2018-09-security-update-for-otrs-framework/");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00028.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"otrs2 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.3.18-1+deb8u7.

We recommend that you upgrade your otrs2 packages.");
  script_tag(name:"summary", value:"Two security vulnerabilities were discovered in OTRS, a Ticket Request
System, that may lead to privilege escalation or arbitrary file write.

CVE-2018-19141

    An attacker who is logged into OTRS as an admin user may manipulate
    the URL to cause execution of JavaScript in the context of OTRS.

CVE-2018-19143

    An attacker who is logged into OTRS as a user may manipulate the
    submission form to cause deletion of arbitrary files that the OTRS
    web server user has write access to.

Please also read the upstream advisory for CVE-2018-19141. If you
think you might be affected then you should consider to run the
mentioned clean-up SQL statements to remove possible affected records.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"otrs", ver:"3.3.18-1+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"otrs2", ver:"3.3.18-1+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}