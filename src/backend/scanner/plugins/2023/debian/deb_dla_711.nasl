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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.711");
  script_cve_id("CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-13 11:29:00 +0000 (Tue, 13 Nov 2018)");

  script_name("Debian: Security Advisory (DLA-711)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-711");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-711");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DLA-711 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2016-8615

If cookie state is written into a cookie jar file that is later read back and used for subsequent requests, a malicious HTTP server can inject new cookies for arbitrary domains into said cookie jar. The issue pertains to the function that loads cookies into memory, which reads the specified file into a fixed-size buffer in a line-by-line manner using the `fgets()` function. If an invocation of fgets() cannot read the whole line into the destination buffer due to it being too small, it truncates the output. This way, a very long cookie (name + value) sent by a malicious server would be stored in the file and subsequently that cookie could be read partially and crafted correctly, it could be treated as a different cookie for another server.

CVE-2016-8616

When re-using a connection, curl was doing case insensitive comparisons of user name and password with the existing connections. This means that if an unused connection with proper credentials exists for a protocol that has connection-scoped credentials, an attacker can cause that connection to be reused if s/he knows the case-insensitive version of the correct password.

CVE-2016-8617

In libcurl's base64 encode function, the output buffer is allocated as follows without any checks on insize: malloc( insize * 4 / 3 + 4 ) On systems with 32-bit addresses in userspace (e.g. x86, ARM, x32), the multiplication in the expression wraps around if insize is at least 1GB of data. If this happens, an undersized output buffer will be allocated, but the full result will be written, thus causing the memory behind the output buffer to be overwritten. Systems with 64 bit versions of the `size_t` type are not affected by this issue.

CVE-2016-8618

The libcurl API function called `curl_maprintf()` can be tricked into doing a double-free due to an unsafe `size_t` multiplication, on systems using 32 bit `size_t` variables. The function is also used internallty in numerous situations. Systems with 64 bit versions of the `size_t` type are not affected by this issue.

CVE-2016-8619

In curl's implementation of the Kerberos authentication mechanism, the function `read_data()` in security.c is used to fill the necessary krb5 structures. When reading one of the length fields from the socket, it fails to ensure that the length parameter passed to realloc() is not set to 0.

CVE-2016-8621

The `curl_getdate` converts a given date string into a numerical timestamp and it supports a range of different formats and possibilites to express a date and time. The underlying date parsing function is also used internally when parsing for example HTTP cookies (possibly received from remote servers) and it can be used when doing conditional HTTP requests.

CVE-2016-8622

The URL percent-encoding decode function in libcurl is called `curl_easy_unescape`. Internally, even if this function would be made to allocate a unescape destination buffer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.26.0-1+wheezy17", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.26.0-1+wheezy17", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.26.0-1+wheezy17", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.26.0-1+wheezy17", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.26.0-1+wheezy17", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.26.0-1+wheezy17", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.26.0-1+wheezy17", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.26.0-1+wheezy17", rls:"DEB7"))) {
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
