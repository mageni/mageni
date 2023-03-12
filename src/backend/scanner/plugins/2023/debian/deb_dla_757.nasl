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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.757");
  script_cve_id("CVE-2016-4412", "CVE-2016-6626", "CVE-2016-9849", "CVE-2016-9850", "CVE-2016-9861", "CVE-2016-9864", "CVE-2016-9865");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-08 01:29:00 +0000 (Sun, 08 Jul 2018)");

  script_name("Debian: Security Advisory (DLA-757)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-757");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-757");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DLA-757 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various security issues where found and fixed in phpmyadmin in wheezy.

CVE-2016-4412 / PMASA-2016-57 A user can be tricked in following a link leading to phpMyAdmin, which after authentication redirects to another malicious site.

CVE-2016-6626 / PMASA-2016-49 In the fix for PMASA-2016-57, we didn't have sufficient checking and was possible to bypass whitelist.

CVE-2016-9849 / PMASA-2016-60 Username deny rules bypass (AllowRoot & Others) by using Null Byte.

CVE-2016-9850 / PMASA-2016-61 Username matching for the allow/deny rules may result in wrong matches and detection of the username in the rule due to non-constant execution time.

CVE-2016-9861 / PMASA-2016-66 In the fix for PMASA-2016-49, we has buggy checks and was possible to bypass whitelist.

CVE-2016-9864 / PMASA-2016-69 Multiple SQL injection vulnerabilities.

CVE-2016-9865 / PMASA-2016-70 Due to a bug in serialized string parsing, it was possible to bypass the protection offered by PMA_safeUnserialize() function.

For Debian 7 Wheezy, these problems have been fixed in version 4:3.4.11.1-2+deb7u7.

We recommend that you upgrade your phpmyadmin packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:3.4.11.1-2+deb7u7", rls:"DEB7"))) {
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
