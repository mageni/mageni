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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2011.2154");
  script_cve_id("CVE-2010-4345", "CVE-2011-0017");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2154)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2154");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2154");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exim4' package(s) announced via the DSA-2154 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A design flaw (CVE-2010-4345) in exim4 allowed the local Debian-exim user to obtain root privileges by specifying an alternate configuration file using the -C option or by using the macro override facility (-D option). Unfortunately, fixing this vulnerability is not possible without some changes in exim4's behaviour. If you use the -C or -D options or use the system filter facility, you should evaluate the changes carefully and adjust your configuration accordingly. The Debian default configuration is not affected by the changes.

The detailed list of changes is described in the NEWS.Debian file in the packages. The relevant sections are also reproduced below.

In addition to that, missing error handling for the setuid/setgid system calls allowed the Debian-exim user to cause root to append log data to arbitrary files (CVE-2011-0017).

For the stable distribution (lenny), these problems have been fixed in version 4.69-9+lenny3.

For the testing distribution (squeeze) and the unstable distribution (sid), these problem have been fixed in version 4.72-4.

Excerpt from the NEWS.Debian file from the packages exim4-daemon-light and exim4-daemon-heavy:

Exim versions up to and including 4.72 are vulnerable to CVE-2010-4345. This is a privilege escalation issue that allows the exim user to gain root privileges by specifying an alternate configuration file using the -C option. The macro override facility (-D) might also be misused for this purpose. In reaction to this security vulnerability upstream has made a number of user visible changes. This package includes these changes. If exim is invoked with the -C or -D option the daemon will not regain root privileges though re-execution. This is usually necessary for local delivery, though. Therefore it is generally not possible anymore to run an exim daemon with -D or -C options. However this version of exim has been built with TRUSTED_CONFIG_LIST=/etc/exim4/trusted_configs. TRUSTED_CONFIG_LIST defines a list of configuration files which are trusted, if a config file is owned by root and matches a pathname in the list, then it may be invoked by the Exim build-time user without Exim relinquishing root privileges. As a hotfix to not break existing installations of mailscanner we have also set WHITELIST_D_MACROS=OUTGOING. i.e. it is still possible to start exim with -DOUTGOING while being able to do local deliveries. If you previously were using -D switches you will need to change your setup to use a separate configuration file. The '.include' mechanism makes this easy. The system filter is run as exim_user instead of root by default. If your setup requies root privileges when running the system filter you will need to set the system_filter_user exim main configuration option.");

  script_tag(name:"affected", value:"'exim4' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"exim4-base", ver:"4.69-9+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-config", ver:"4.69-9+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy-dbg", ver:"4.69-9+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.69-9+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light-dbg", ver:"4.69-9+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light", ver:"4.69-9+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-dbg", ver:"4.69-9+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-dev", ver:"4.69-9+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4", ver:"4.69-9+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"eximon4", ver:"4.69-9+lenny3", rls:"DEB5"))) {
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
