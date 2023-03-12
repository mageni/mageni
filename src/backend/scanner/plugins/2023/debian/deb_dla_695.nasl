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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.695");
  script_cve_id("CVE-2016-7980", "CVE-2016-7981", "CVE-2016-7982", "CVE-2016-7998", "CVE-2016-7999");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-24 01:29:00 +0000 (Wed, 24 May 2017)");

  script_name("Debian: Security Advisory (DLA-695)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-695");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-695");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'spip' package(s) announced via the DLA-695 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in SPIP, a website engine for publishing written in PHP.

CVE-2016-7980

Nicolas Chatelain of Sysdream Labs discovered a cross-site request forgery (CSRF) vulnerability in the valider_xml action of SPIP. This allows remote attackers to make use of potential additional vulnerabilities such as the one described in CVE-2016-7998.

CVE-2016-7981

Nicolas Chatelain of Sysdream Labs discovered a reflected cross-site scripting attack (XSS) vulnerability in the validater_xml action of SPIP. An attacker could take advantage of this vulnerability to inject arbitrary code by tricking an administrator to open a malicious link.

CVE-2016-7982

Nicolas Chatelain of Sysdream Labs discovered a file enumeration / path traversal attack in the validator_xml action of SPIP. An attacker could use this to enumerate files in an arbitrary directory on the file system.

CVE-2016-7998

Nicolas Chatelain of Sysdream Labs discovered a possible PHP code execution vulnerability in the template compiler/composer function of SPIP. In combination with the XSS and CSRF vulnerabilities described in this advisory, a remote attacker could take advantage of this to execute arbitrary PHP code on the server.

CVE-2016-7999

Nicolas Chatelain of Sysdream Labs discovered a server side request forgery in the valider_xml action of SPIP. Attackers could take advantage of this vulnerability to send HTTP or FTP requests to remote servers that they don't have direct access to, possibly bypassing access controls such as a firewall.

For Debian 7 Wheezy, these problems have been fixed in version 2.1.17-1+deb7u6.

We recommend that you upgrade your spip packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'spip' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"2.1.17-1+deb7u6", rls:"DEB7"))) {
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
