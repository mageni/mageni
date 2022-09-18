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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.59.1");
  script_cve_id("CVE-2004-1177");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-59-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-59-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-59-1");
  script_xref(name:"URL", value:"https://bugzilla.ubuntu.com/4892");
  script_xref(name:"URL", value:"http://bugs.debian.org/285839");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mailman' package(s) announced via the USN-59-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer discovered a cross-site scripting vulnerability in
mailman's automatically generated error messages. An attacker could
craft an URL containing JavaScript (or other content embedded into
HTML) which triggered a mailman error page. When an unsuspecting user
followed this URL, the malicious content was copied unmodified to the
error page and executed in the context of this page.

Juha-Matti Tapio discovered an information disclosure in the private
rosters management. Everybody could check whether a specified email
address was subscribed to a private mailing list by looking at the
error message. This bug was Ubuntu/Debian specific.

Important note:

There is currently another known vulnerability: when an user
subscribes to a mailing list without choosing a password, mailman
automatically generates one. However, there are only about 5 million
different possible passwords which allows brute force attacks.

A different password generation algorithm already exists, but is
currently too immature to be put into a stable release security
update. Therefore it is advisable to always explicitly choose a
password for subscriptions, at least until this gets fixed in Warty
Warthog.

See [link moved to references] for details.");

  script_tag(name:"affected", value:"'mailman' package(s) on Ubuntu 4.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mailman", ver:"2.1.5-1ubuntu2.2", rls:"UBUNTU4.10"))) {
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
