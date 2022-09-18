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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.149.1");
  script_cve_id("CVE-2004-0718", "CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-149-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU5\.04");

  script_xref(name:"Advisory-ID", value:"USN-149-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-149-1");
  script_xref(name:"URL", value:"http://addons.mozilla.org");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-firefox' package(s) announced via the USN-149-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Secunia.com reported that one of the recent security patches in
Firefox reintroduced the frame injection patch that was originally
known as CAN-2004-0718. This allowed a malicious web site to spoof the
contents of other web sites. (CAN-2005-1937)

In several places the browser user interface did not correctly
distinguish between true user events, such as mouse clicks or
keystrokes, and synthetic events genenerated by web content. This
could be exploited by malicious web sites to generate e. g. mouse
clicks that install malicious plugins. Synthetic events are now
prevented from reaching the browser UI entirely. (CAN-2005-2260)

Scripts in XBL controls from web content continued to be run even when
Javascript was disabled. This could be combined with most script-based
exploits to attack people running vulnerable versions who thought
disabling Javascript would protect them. (CAN-2005-2261)

Matthew Mastracci discovered a flaw in the addons installation
launcher. By forcing a page navigation immediately after calling the
install method a callback function could end up running in the context
of the new page selected by the attacker. This callback script could
steal data from the new page such as cookies or passwords, or perform
actions on the user's behalf such as make a purchase if the user is
already logged into the target site. However, the default settings
allow only [link moved to references] to bring up this install dialog.
This could only be exploited if users have added untrustworthy sites
to the installation allowlist, and if a malicious site can convince
you to install from their site. (CAN-2005-2263)

Kohei Yoshino discovered a Javascript injection vulnerability in the
sidebar. Sites can use the _search target to open links in the Firefox
sidebar. A missing security check allowed the sidebar to inject
'data:' URLs containing scripts into any page open in the browser.
This could be used to steal cookies, passwords or other sensitive
data. (CAN-2005-2264)

The function for version comparison in the addons installer did not
properly verify the type of its argument. By passing specially crafted
Javascript objects to it, a malicious web site could crash the browser
and possibly even execute arbitrary code with the privilege of the
user account Firefox runs in. (CAN-2005-2265)

A child frame can call top.focus() even if the framing page comes from
a different origin and has overridden the focus() routine. Andreas
Sandblad discovered that the call is made in the context of the child
frame. This could be exploited to steal cookies and passwords from the
framed page, or take actions on behalf of a signed-in user. However,
web sites with above properties are not very common. (CAN-2005-2266)

Several media players, for example Flash and QuickTime, support
scripted content with the ability to open URLs in the default browser.
The default behavior for Firefox was to replace the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Ubuntu 5.04.");

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

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"1.0.2-0ubuntu5.4", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.2-0ubuntu5.4", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.2-0ubuntu5.4", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.2-0ubuntu5.4", rls:"UBUNTU5.04"))) {
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
