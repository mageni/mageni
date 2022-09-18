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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.72.1");
  script_cve_id("CVE-2005-0155", "CVE-2005-0156");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-72-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-72-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-72-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the USN-72-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two exploitable vulnerabilities involving setuid-enabled perl scripts
have been discovered. The package 'perl-suid' provides a wrapper
around perl which allows to use setuid-root perl scripts, i.e.
user-callable Perl scripts which have full root privileges.

Previous versions allowed users to overwrite arbitrary files by
setting the PERLIO_DEBUG environment variable and calling an arbitrary
setuid-root perl script. The file that PERLIO_DEBUG points to was then
overwritten by Perl debug messages. This did not allow precise control
over the file content, but could destroy important data. PERLIO_DEBUG
is now ignored for setuid scripts. (CAN-2005-0155)

In addition, calling a setuid-root perl script with a very long path
caused a buffer overflow if PERLIO_DEBUG was set. This buffer overflow
could be exploited to execute arbitrary files with full root
privileges. (CAN-2005-0156)");

  script_tag(name:"affected", value:"'perl' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libcgi-fast-perl", ver:"5.8.4-2ubuntu0.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libperl-dev", ver:"5.8.4-2ubuntu0.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libperl5.8", ver:"5.8.4-2ubuntu0.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-base", ver:"5.8.4-2ubuntu0.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-debug", ver:"5.8.4-2ubuntu0.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-doc", ver:"5.8.4-2ubuntu0.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-modules", ver:"5.8.4-2ubuntu0.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-suid", ver:"5.8.4-2ubuntu0.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.8.4-2ubuntu0.3", rls:"UBUNTU4.10"))) {
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
