# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.255");
  script_cve_id("CVE-2015-2665", "CVE-2015-2967", "CVE-2015-4342", "CVE-2015-4454");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-255)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-255");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-255");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cacti' package(s) announced via the DLA-255 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities (cross-site scripting and SQL injection) have been discovered in Cacti, a web interface for graphing of monitoring systems.

We recommend that you upgrade your cacti packages.

CVE-2015-2665

Cross-site scripting (XSS) vulnerability in Cacti before 0.8.8d allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.

CVE-2015-4342

SQL Injection and Location header injection from cdef id

CVE-2015-4454

SQL injection vulnerability in the get_hash_graph_template function in lib/functions.php in Cacti before 0.8.8d allows remote attackers to execute arbitrary SQL commands via the graph_template_id parameter to graph_templates.php

Unassigned CVE SQL injection VN:JVN#78187936 / TN:JPCERT#98968540 SQL injection vulnerability in the settings page");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.7g-1+squeeze6", rls:"DEB6"))) {
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
