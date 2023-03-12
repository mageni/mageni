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
  script_oid("1.3.6.1.4.1.25623.1.0.893336");
  script_cve_id("CVE-2021-27515", "CVE-2021-3664", "CVE-2022-0512", "CVE-2022-0639", "CVE-2022-0686", "CVE-2022-0691");
  script_tag(name:"creation_date", value:"2023-02-23 02:00:24 +0000 (Thu, 23 Feb 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 19:28:00 +0000 (Mon, 28 Feb 2022)");

  script_name("Debian: Security Advisory (DLA-3336)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3336");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3336");
  script_xref(name:"URL", value:"http://example.com");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/node-url-parse");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-url-parse' package(s) announced via the DLA-3336 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in node-types-url-parse, a Node.js module used to parse URLs, which may result in authorization bypass or redirection to untrusted sites.

CVE-2021-3664

url-parse mishandles certain uses of a single (back)slash such as https: and https:/, and interprets the URI as a relative path. Browsers accept a single backslash after the protocol, and treat it as a normal slash, while url-parse sees it as a relative path. Depending on library usage, this may result in allow/block list bypasses, SSRF attacks, open redirects, or other undesired behavior.

CVE-2021-27515

Using backslash in the protocol is valid in the browser, while url-parse thinks it's a relative path. An application that validates a URL using url-parse might pass a malicious link.

CVE-2022-0512

Incorrect handling of username and password can lead to failure to properly identify the hostname, which in turn could result in authorization bypass.

CVE-2022-0639

Incorrect conversion of @ characters in protocol in the href field can lead to lead to failure to properly identify the hostname, which in turn could result in authorization bypass.

CVE-2022-0686

Rohan Sharma reported that url-parse is unable to find the correct hostname when no port number is provided in the URL, such as in [link moved to references]:. This could in turn result in SSRF attacks, open redirects or any other vulnerability which depends on the hostname field of the parsed URL.

CVE-2022-0691

url-parse is unable to find the correct hostname when the URL contains a backspace b character. This tricks the parser into interpreting the URL as a relative path, bypassing all hostname checks. It can also lead to false positive in extractProtocol().

For Debian 10 buster, these problems have been fixed in version 1.2.0-2+deb10u2.

We recommend that you upgrade your node-url-parse packages.

For the detailed security status of node-url-parse please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'node-url-parse' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"node-url-parse", ver:"1.2.0-2+deb10u2", rls:"DEB10"))) {
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
