# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891716");
  script_version("$Revision: 14308 $");
  script_cve_id("CVE-2019-9187");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1716-1] ikiwiki security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:12:26 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-19 00:00:00 +0100 (Tue, 19 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00018.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"ikiwiki on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
3.20141016.4+deb8u1.

We recommend that you upgrade your ikiwiki packages. In addition it is also
recommended that you have liblwpx-paranoidagent-perl installed, which listed in
the recommends field of ikiwiki.");
  script_tag(name:"summary", value:"The ikiwiki maintainers discovered that the aggregate plugin did not use
LWPx::ParanoidAgent. On sites where the aggregate plugin is enabled, authorized
wiki editors could tell ikiwiki to fetch potentially undesired URIs even if
LWPx::ParanoidAgent was installed:

local files via file: URIs
other URI schemes that might be misused by attackers, such as gopher:
hosts that resolve to loopback IP addresses (127.x.x.x)
hosts that resolve to RFC 1918 IP addresses (192.168.x.x etc.)

This could be used by an attacker to publish information that should not have
been accessible, cause denial of service by requesting 'tarpit' URIs that are
slow to respond, or cause undesired side-effects if local web servers implement
'unsafe' GET requests. (CVE-2019-9187)

Additionally, if liblwpx-paranoidagent-perl is not installed, the
blogspam, openid and pinger plugins would fall back to LWP, which is
susceptible to similar attacks. This is unlikely to be a practical problem for
the blogspam plugin because the URL it requests is under the control of the
wiki administrator, but the openid plugin can request URLs controlled by
unauthenticated remote users, and the pinger plugin can request URLs controlled
by authorized wiki editors.

This is addressed in ikiwiki 3.20190228 as follows, with the same fixes
backported to Debian 9 in version 3.20170111.1:

  * URI schemes other than http: and https: are not accepted, preventing access
to file:, gopher:, etc.

  * If a proxy is configured in the ikiwiki setup file, it is used for all
outgoing http: and https: requests. In this case the proxy is responsible for
blocking any requests that are undesired, including loopback or RFC 1918
addresses.

  * If a proxy is not configured, and liblwpx-paranoidagent-perl is installed, it
will be used. This prevents loopback and RFC 1918 IP addresses, and sets a
timeout to avoid denial of service via 'tarpit' URIs.

  * Otherwise, the ordinary LWP user-agent will be used. This allows requests to
loopback and RFC 1918 IP addresses, and has less robust timeout behaviour.
We are not treating this as a vulnerability: if this behaviour is not
acceptable for your site, please make sure to install LWPx::ParanoidAgent or
disable the affected plugins.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ikiwiki", ver:"3.20141016.4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}