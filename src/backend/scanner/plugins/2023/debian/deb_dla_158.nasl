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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.158");
  script_cve_id("CVE-2014-9472", "CVE-2015-1165", "CVE-2015-1464");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DLA-158)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-158");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-158");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'request-tracker3.8' package(s) announced via the DLA-158 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Request Tracker, an extensible trouble-ticket tracking system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-9472

Christian Loos discovered a remote denial of service vulnerability, exploitable via the email gateway and affecting any installation which accepts mail from untrusted sources. Depending on RT's logging configuration, a remote attacker can take advantage of this flaw to cause CPU and excessive disk usage.

CVE-2015-1165

Christian Loos discovered an information disclosure flaw which may reveal RSS feeds URLs, and thus ticket data.

CVE-2015-1464

It was discovered that RSS feed URLs can be leveraged to perform session hijacking, allowing a user with the URL to log in as the user that created the feed.

For the oldstable distribution (squeeze), these problems have been fixed in version 3.8.8-7+squeeze9.

We recommend that you upgrade your request-tracker3.8 packages.");

  script_tag(name:"affected", value:"'request-tracker3.8' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker3.8", ver:"3.8.8-7+squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-apache2", ver:"3.8.8-7+squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-clients", ver:"3.8.8-7+squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-db-mysql", ver:"3.8.8-7+squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-db-postgresql", ver:"3.8.8-7+squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-db-sqlite", ver:"3.8.8-7+squeeze8", rls:"DEB6"))) {
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
