# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2017.3373.1");
  script_cve_id("CVE-2016-8743", "CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-3373-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3373-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3373-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-3373-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Emmanuel Dreyfus discovered that third-party modules using the
ap_get_basic_auth_pw() function outside of the authentication phase may
lead to authentication requirements being bypassed. This update adds a new
ap_get_basic_auth_components() function for use by third-party modules.
(CVE-2017-3167)

Vasileios Panopoulos discovered that the Apache mod_ssl module may crash
when third-party modules call ap_hook_process_connection() during an HTTP
request to an HTTPS port. (CVE-2017-3169)

Javier Jimenez discovered that the Apache HTTP Server incorrectly handled
parsing certain requests. A remote attacker could possibly use this issue
to cause the Apache HTTP Server to crash, resulting in a denial of service.
(CVE-2017-7668)

ChenQin and Hanno Bock discovered that the Apache mod_mime module
incorrectly handled certain Content-Type response headers. A remote
attacker could possibly use this issue to cause the Apache HTTP Server to
crash, resulting in a denial of service. (CVE-2017-7679)

David Dennerline and Regis Leroy discovered that the Apache HTTP Server
incorrectly handled unusual whitespace when parsing requests, contrary to
specifications. When being used in combination with a proxy or backend
server, a remote attacker could possibly use this issue to perform an
injection attack and pollute cache. This update may introduce compatibility
issues with clients that do not strictly follow HTTP protocol
specifications. A new configuration option 'HttpProtocolOptions Unsafe' can
be used to revert to the previous unsafe behaviour in problematic
environments. (CVE-2016-8743)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.22-1ubuntu1.12", rls:"UBUNTU12.04 LTS"))) {
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
