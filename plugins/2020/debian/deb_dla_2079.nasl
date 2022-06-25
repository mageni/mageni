# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892079");
  script_version("2020-01-30T04:00:09+0000");
  script_cve_id("CVE-2020-1765", "CVE-2020-1766", "CVE-2020-1767");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-01-30 04:00:09 +0000 (Thu, 30 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-30 04:00:09 +0000 (Thu, 30 Jan 2020)");
  script_name("Debian LTS: Security Advisory for otrs2 (DLA-2079-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00027.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2079-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'otrs2'
  package(s) announced via the DLA-2079-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the otrs2 package that
may lead to unauthorized access, remote code execution and spoofing.

CVE-2020-1765

An improper control of parameters allows the spoofing of the from
fields of the following screens: AgentTicketCompose,
AgentTicketForward, AgentTicketBounce.

CVE-2020-1766

Due to improper handling of uploaded images it is possible in very
unlikely and rare conditions to force the agents browser to execute
malicious javascript from a special crafted SVG file rendered as
inline jpg file.

CVE-2020-1767

Unauthorized view of drafts, change the text completely and send it
in the name of draft owner. For the customer it will not be visible
that the message was sent by another agent.");

  script_tag(name:"affected", value:"'otrs2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.3.18-1+deb8u13.

We recommend that you upgrade your otrs2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"otrs", ver:"3.3.18-1+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"3.3.18-1+deb8u13", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
