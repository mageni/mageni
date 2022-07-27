# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891877");
  script_version("2019-08-16T08:19:10+0000");
  script_cve_id("CVE-2018-11563", "CVE-2019-12248", "CVE-2019-12746", "CVE-2019-13458");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-08-16 08:19:10 +0000 (Fri, 16 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-15 02:00:15 +0000 (Thu, 15 Aug 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1877-1] otrs2 security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00018.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1877-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'otrs2'
  package(s) announced via the DSA-1877-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been fixed in otrs2, a well known trouble
ticket system.

CVE-2018-11563

An attacker who is logged into OTRS as a customer can use the ticket
overview screen to disclose internal article information of their
customer tickets.

CVE-2019-12746

A user logged into OTRS as an agent might unknowingly disclose their
session ID by sharing the link of an embedded ticket article with
third parties. This identifier can be then potentially abused in
order to impersonate the agent user.

CVE-2019-13458

An attacker who is logged into OTRS as an agent user with
appropriate permissions can leverage OTRS tags in templates in order
to disclose hashed user passwords.

Due to an incomplete fix for CVE-2019-12248, viewing email attachments
was no longer possible. This update correctly implements the new
Ticket::Fronted::BlockLoadingRemoteContent option.");

  script_tag(name:"affected", value:"'otrs2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.3.18-1+deb8u11.

We recommend that you upgrade your otrs2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"otrs", ver:"3.3.18-1+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"3.3.18-1+deb8u11", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);