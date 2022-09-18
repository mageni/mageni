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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.320.1");
  script_cve_id("CVE-2006-0996", "CVE-2006-1490", "CVE-2006-1494", "CVE-2006-1608", "CVE-2006-1990", "CVE-2006-1991", "CVE-2006-2563", "CVE-2006-2660", "CVE-2006-3011", "CVE-2006-3016", "CVE-2006-3017", "CVE-2006-3018");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T08:45:11+0000");
  script_tag(name:"last_modification", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.04|5\.10|6\.06\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-320-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-320-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php4, php5' package(s) announced via the USN-320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The phpinfo() PHP function did not properly sanitize long strings. A
remote attacker could use this to perform cross-site scripting attacks
against sites that have publicly-available PHP scripts that call
phpinfo(). Please note that it is not recommended to publicly expose
phpinfo(). (CVE-2006-0996)

An information disclosure has been reported in the
html_entity_decode() function. A script which uses this function to
process arbitrary user-supplied input could be exploited to expose a
random part of memory, which could potentially reveal sensitive data.
(CVE-2006-1490)

The wordwrap() function did not sufficiently check the validity of the
'break' argument. An attacker who could control the string passed to
the 'break' parameter could cause a heap overflow, however, this
should not happen in practical applications. (CVE-2006-1990)

The substr_compare() function did not sufficiently check the validity
of the 'offset' argument. A script which passes untrusted user-defined
values to this parameter could be exploited to crash the PHP
interpreter. (CVE-2006-1991)

In certain situations, using unset() to delete a hash entry could
cause the deletion of the wrong element, which would leave the
specified variable defined. This could potentially cause information
disclosure in security-relevant operations. (CVE-2006-3017)

In certain situations the session module attempted to close a data
file twice, which led to memory corruption. This could potentially be
exploited to crash the PHP interpreter, though that could not be
verified. (CVE-2006-3018)

This update also fixes various bugs which allowed local scripts
to bypass open_basedir and 'safe mode' restrictions by passing special
arguments to tempnam() (CVE-2006-1494, CVE-2006-2660), copy()
(CVE-2006-1608), the curl module (CVE-2006-2563), or error_log()
(CVE-2006-3011).");

  script_tag(name:"affected", value:"'php4, php5' package(s) on Ubuntu 5.04, Ubuntu 5.10, Ubuntu 6.06.");

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

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php4", ver:"4:4.3.10-10ubuntu4.5", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-cgi", ver:"4:4.3.10-10ubuntu4.5", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-cli", ver:"4:4.3.10-10ubuntu4.5", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.0.5-2ubuntu1.3", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.0.5-2ubuntu1.3", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.0.5-2ubuntu1.3", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-curl", ver:"5.0.5-2ubuntu1.3", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.1.2-1ubuntu3.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.1.2-1ubuntu3.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.1.2-1ubuntu3.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-curl", ver:"5.1.2-1ubuntu3.1", rls:"UBUNTU6.06 LTS"))) {
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
