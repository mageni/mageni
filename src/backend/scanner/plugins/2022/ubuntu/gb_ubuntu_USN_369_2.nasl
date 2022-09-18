# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.369.2");
  script_cve_id("CVE-2006-5540", "CVE-2006-5541", "CVE-2006-5542");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-369-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.10");

  script_xref(name:"Advisory-ID", value:"USN-369-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-369-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-8.1' package(s) announced via the USN-369-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-369-1 fixed three minor PostgreSQL 8.1 vulnerabilities for Ubuntu 6.06 LTS.
This update provides the corresponding update for Ubuntu 6.10.

Original advisory details:

 Michael Fuhr discovered an incorrect type check when handling unknown
 literals. By attempting to coerce such a literal to the ANYARRAY type,
 a local authenticated attacker could cause a server crash. (CVE-2006-5541)

 Josh Drake and Alvaro Herrera reported a crash when using aggregate
 functions in UPDATE statements. A local authenticated attacker could
 exploit this to crash the server backend. This update disables this
 construct, since it is not very well defined and forbidden by the SQL
 standard. (CVE-2006-5540)

 Sergey Koposov discovered a flaw in the duration logging. This could
 cause a server crash under certain circumstances. (CVE-2006-5542)

 Please note that these flaws can usually not be exploited through web
 and other applications that use a database and are exposed to
 untrusted input, so these flaws do not pose a threat in usual setups.");

  script_tag(name:"affected", value:"'postgresql-8.1' package(s) on Ubuntu 6.10.");

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

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.1", ver:"8.1.4-7ubuntu0.1", rls:"UBUNTU6.10"))) {
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
