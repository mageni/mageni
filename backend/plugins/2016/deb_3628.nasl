# OpenVAS Vulnerability Test
# $Id: deb_3628.nasl 3784 2016-08-02 08:07:52Z antu123 $
# Auto-generated from advisory DSA 3628-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703628");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-1238", "CVE-2016-6185");
  script_name("Debian Security Advisory DSA 3628-1 (perl - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-02 10:56:30 +0530 (Tue, 02 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3628.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"perl on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 5.20.2-3+deb8u6. Additionally this update
includes the following updated packages to address optional module loading
vulnerabilities related to CVE-2016-1238
,
or to address build failures which occur when '.' is removed from @INC:

cdbs 0.4.130+deb8u1debhelper 9.20150101+deb8u2devscripts 2.15.3+deb8u12exim4
4.84.2-2+deb8u12libintl-perl 1.23-1+deb8u12libmime-charset-perl
1.011.1-1+deb8u22libmime-encwords-perl 1.014.3-1+deb8u12libmodule-build-perl
0.421000-2+deb8u12libnet-dns-perl 0.81-2+deb8u12libsys-syslog-perl
0.33-1+deb8u12libunicode-linebreak-perl 0.0.20140601-2+deb8u22
We recommend that you upgrade your perl packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities were discovered in
the implementation of the Perl programming language. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2016-1238
John Lightsey and Todd Rinaldo reported that the opportunistic
loading of optional modules can make many programs unintentionally
load code from the current working directory (which might be changed
to another directory without the user realising) and potentially
leading to privilege escalation, as demonstrated in Debian with
certain combinations of installed packages.

The problem relates to Perl loading modules from the includes
directory array ('@INC') in which the last element is the current
directory ('.'). That means that, when perl
wants to load a module
(during first compilation or during lazy loading of a module in run
time), perl will look for the module in the current directory at the
end, since '.' is the last include directory in its array of include
directories to seek. The issue is with requiring libraries that are
in '.' but are not otherwise installed.

With this update several modules which are known to be vulnerable
are updated to not load modules from current directory.

Additionally the update allows configurable removal of '.' from @INC
in /etc/perl/sitecustomize.pl for a transitional period. It is
recommended to enable this setting if the possible breakage for a
specific site has been evaluated. Problems in packages provided in
Debian resulting from the switch to the removal of '.' from @INC
should be reported to the Perl maintainers at
perl@packages.debian.org .

It is planned to switch to the default removal of '.' in @INC in a
subsequent update to perl via a point release if possible, and in
any case for the upcoming stable release Debian 9 (stretch).

CVE-2016-6185
It was discovered that XSLoader, a core module from Perl to
dynamically load C libraries into Perl code, could load shared
library from incorrect location. XSLoader uses caller() information
to locate the .so file to load. This can be incorrect if
XSLoader::load() is called in a string eval. An attacker can take
advantage of this flaw to execute arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libperl-dev", ver:"5.20.2-3+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl5.20", ver:"5.20.2-3+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl", ver:"5.20.2-3+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-base", ver:"5.20.2-3+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-debug", ver:"5.20.2-3+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-doc", ver:"5.20.2-3+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-modules", ver:"5.20.2-3+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}