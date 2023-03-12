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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.565");
  script_cve_id("CVE-2016-1238", "CVE-2016-6185");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 13:20:00 +0000 (Thu, 10 Sep 2020)");

  script_name("Debian: Security Advisory (DLA-565)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-565");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-565");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'perl' package(s) announced via the DLA-565 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the implementation of the Perl programming language. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-1238

John Lightsey and Todd Rinaldo reported that the opportunistic loading of optional modules can make many programs unintentionally load code from the current working directory (which might be changed to another directory without the user realising) and potentially leading to privilege escalation, as demonstrated in Debian with certain combinations of installed packages.

The problem relates to Perl loading modules from the includes directory array ('@INC') in which the last element is the current directory ('.'). That means that, when perl wants to load a module (during first compilation or during lazy loading of a module in run time), perl will look for the module in the current directory at the end, since '.' is the last include directory in its array of include directories to seek. The issue is with requiring libraries that are in '.' but are not otherwise installed.

With this update several modules which are known to be vulnerable are updated to not load modules from current directory.

Additionally the update allows configurable removal of '.' from @INC in /etc/perl/sitecustomize.pl for a transitional period. It is recommended to enable this setting if the possible breakage for a specific site has been evaluated. Problems in packages provided in Debian resulting from the switch to the removal of '.' from @INC should be reported to the Perl maintainers at perl@packages.debian.org .

CVE-2016-6185

It was discovered that XSLoader, a core module from Perl to dynamically load C libraries into Perl code, could load shared library from incorrect location. XSLoader uses caller() information to locate the .so file to load. This can be incorrect if XSLoader::load() is called in a string eval. An attacker can take advantage of this flaw to execute arbitrary code.

For Debian 7 Wheezy, these problems have been fixed in version 5.14.2-21+deb7u4.

We recommend that you upgrade your perl packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'perl' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcgi-fast-perl", ver:"5.14.2-21+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libperl-dev", ver:"5.14.2-21+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libperl5.14", ver:"5.14.2-21+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-base", ver:"5.14.2-21+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-debug", ver:"5.14.2-21+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-doc", ver:"5.14.2-21+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-modules", ver:"5.14.2-21+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.14.2-21+deb7u4", rls:"DEB7"))) {
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
