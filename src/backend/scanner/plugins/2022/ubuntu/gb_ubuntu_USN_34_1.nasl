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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2004.34.1");
  script_cve_id("CVE-2003-0190");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-34-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-34-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-34-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the USN-34-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"@Mediaservice.net discovered two information leaks in the OpenSSH
server. When using password authentication, an attacker could
test whether a login name exists by measuring the time between
failed login attempts, i. e. the time after which the 'password:'
prompt appears again.

A similar issue affects systems which do not allow root logins over
ssh ('PermitRootLogin no'). By measuring the time between login
attempts an attacker could check whether a given root password is
correct. This allowed determining weak root passwords using a brute
force attack.");

  script_tag(name:"affected", value:"'openssh' package(s) on Ubuntu 4.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"3.8.1p1-11ubuntu3.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"3.8.1p1-11ubuntu3.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"3.8.1p1-11ubuntu3.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh", ver:"3.8.1p1-11ubuntu3.1", rls:"UBUNTU4.10"))) {
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
