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
  script_oid("1.3.6.1.4.1.25623.1.0.893293");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2018-16384", "CVE-2020-22669", "CVE-2021-35368", "CVE-2022-29956", "CVE-2022-39955", "CVE-2022-39956", "CVE-2022-39957", "CVE-2022-39958");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-09 20:06:00 +0000 (Tue, 09 Nov 2021)");
  script_tag(name:"creation_date", value:"2023-01-31 02:00:09 +0000 (Tue, 31 Jan 2023)");
  script_name("Debian LTS: Security Advisory for modsecurity-crs (DLA-3293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00033.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3293-1");
  script_xref(name:"Advisory-ID", value:"DLA-3293-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/924352");
  script_xref(name:"URL", value:"https://bugs.debian.org/992000");
  script_xref(name:"URL", value:"https://bugs.debian.org/1021137");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'modsecurity-crs'
  package(s) announced via the DLA-3293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in modsecurity-crs, a set of generic attack
detection rules for use with ModSecurity or compatible web application
firewalls, which allows remote attackers to bypass the web applications
firewall.

If you are using modsecurity-crs with apache2 / libapache2-modsecurity, please
make sure to review your modsecurity configuration, usually
/etc/modsecurity/modsecurity.conf, against the updated recommended
configuration, available in /etc/modsecurity/modsecurity.conf-recommended:
Some of the changes to the recommended rules are required to avoid WAF bypasses
in certain circumstances.

Please note that CVE-2022-39956 requires an updated modsecurity-apache package,
which has been previously uploaded to buster-security, see Debian LTS Advisory
DLA-3283-1 for details.

If you are using some other solution in connection with the
modsecurity-ruleset, for example one that it is using libmodsecurity3, your
solution might error out with an error message like 'Error creating rule:
Unknown variable: MULTIPART_PART_HEADERS'. In this case you can disable the
mitigation for CVE-2022-29956 by removing the rule file
REQUEST-922-MULTIPART-ATTACK.conf. However, be aware that this will disable
the protection and could allow attackers to bypass your Web Application
Firewall.

There is no package in Debian which depends on libmodsecurity3, so if you are
only using software which is available from Debian, you are not affected by
this limitation.

Kudos to @airween for the support and help while perparing the update.

CVE-2018-16384

A SQL injection bypass (aka PL1 bypass) exists in OWASP ModSecurity Core Rule
Set (owasp-modsecurity-crs) through v3.1.0-rc3 via {`a`b} where a is a special
function name (such as 'if') and b is the SQL statement to be executed.

CVE-2020-22669

Modsecurity owasp-modsecurity-crs 3.2.0 (Paranoia level at PL1) has a SQL
injection bypass vulnerability. Attackers can use the comment characters and
variable assignments in the SQL syntax to bypass Modsecurity WAF protection and
implement SQL injection attacks on Web applications.

CVE-2022-39955

The OWASP ModSecurity Core Rule Set (CRS) is affected by a partial rule set
bypass by submitting a specially crafted HTTP Content-Type header field that
indicates multiple character encoding schemes. A vulnerable back-end can
potentially be exploited by declaring multiple Content-Type 'charset' names and
therefore bypassing the configurable CRS Content-Type header 'charset' allow
list. An encoded payload can bypass CRS detection this way and may then be
decoded by the backend. The legacy CRS versions 3.0.x and 3.1.x are affected,
as well as the current ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'modsecurity-crs' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
3.2.3-0+deb10u3.

We recommend that you upgrade your modsecurity-crs packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"modsecurity-crs", ver:"3.2.3-0+deb10u3", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
