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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2017.1205");
  script_cve_id("CVE-2017-12867", "CVE-2017-12868", "CVE-2017-12869", "CVE-2017-12872", "CVE-2017-12873", "CVE-2017-12874");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-1205)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1205");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1205");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'simplesamlphp' package(s) announced via the DLA-1205 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The simplesamlphp package in wheezy is vulnerable to multiple attacks on authentication-related code, leading to unauthorized access and information disclosure.

CVE-2017-12867

The SimpleSAML_Auth_TimeLimitedToken class allows attackers with access to a secret token to extend its validity period by manipulating the prepended time offset.

CVE-2017-12869

The multiauth module allows remote attackers to bypass authentication context restrictions and use an authentication source defined in config/authsources.php via vectors related to improper validation of user input.

CVE-2017-12872 / CVE-2017-12868 The (1) Htpasswd authentication source in the authcrypt module and (2) SimpleSAML_Session class in SimpleSAMLphp 1.14.11 and earlier allow remote iattackers to conduct timing side-channel attacks by leveraging use of the standard comparison operator to compare secret material against user input. CVE-2017-12868 was a about an improper fix of CVE-2017-12872 in the initial patch released by upstream. We have used the correct patch.

CVE-2017-12873

SimpleSAMLphp might allow attackers to obtain sensitive information, gain unauthorized access, or have unspecified other impacts by leveraging incorrect persistent NameID generation when an Identity Provider (IdP) is misconfigured.

CVE-2017-12874

The InfoCard module for SimpleSAMLphp allows attackers to spoof XML messages by leveraging an incorrect check of return values in signature validation utilities.

For Debian 7 Wheezy, these problems have been fixed in version 1.9.2-1+deb7u1.

We recommend that you upgrade your simplesamlphp packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'simplesamlphp' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"simplesamlphp", ver:"1.9.2-1+deb7u1", rls:"DEB7"))) {
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
