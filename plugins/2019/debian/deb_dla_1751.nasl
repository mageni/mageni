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
  script_oid("1.3.6.1.4.1.25623.1.0.891751");
  script_version("2019-04-09T02:00:07+0000");
  script_cve_id("CVE-2018-10242", "CVE-2018-10243");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-09 02:00:07 +0000 (Tue, 09 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-09 02:00:07 +0000 (Tue, 09 Apr 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1751-1] suricata security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/04/msg00010.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1751-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'suricata'
  package(s) announced via the DSA-1751-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in suricata, the network threat
detection engine:

CVE-2018-10242

Missing length check causing out-of-bounds read in SSHParseBanner
(app-layer-ssh.c). Remote attackers might leverage this vulnerability
to cause DoS or potentially unauthorized disclosure of information.

CVE-2018-10243

Unexpected end of Authorization field causing heap-based buffer
over-read in htp_parse_authorization_digest (htp_parsers.c, from the
embedded copy of LibHTP). Remote attackers might leverage this
vulnerability to cause DoS or potentially unauthorized disclosure of
information.");

  script_tag(name:"affected", value:"'suricata' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.0.7-2+deb8u4.

We recommend that you upgrade your suricata packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"suricata", ver:"2.0.7-2+deb8u4", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);