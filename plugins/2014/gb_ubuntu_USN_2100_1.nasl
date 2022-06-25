###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2100_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for pidgin USN-2100-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841705");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-02-11 10:44:51 +0530 (Tue, 11 Feb 2014)");
  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479",
                "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484",
                "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490",
                "CVE-2014-0020");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for pidgin USN-2100-1");

  script_tag(name:"affected", value:"pidgin on Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Thijs Alkemade and Robert Vehse discovered that Pidgin
incorrectly handled the Yahoo! protocol. A remote attacker could use this issue
to cause Pidgin to crash, resulting in a denial of service. (CVE-2012-6152)

Jaime Breva Ribes discovered that Pidgin incorrectly handled the XMPP
protocol. A remote attacker could use this issue to cause Pidgin to crash,
resulting in a denial of service. (CVE-2013-6477)

It was discovered that Pidgin incorrecly handled long URLs. A remote
attacker could use this issue to cause Pidgin to crash, resulting in a
denial of service. (CVE-2013-6478)

Jacob Appelbaum discovered that Pidgin incorrectly handled certain HTTP
responses. A malicious remote server or a man in the middle could use this
issue to cause Pidgin to crash, resulting in a denial of service.
(CVE-2013-6479)

Daniel Atallah discovered that Pidgin incorrectly handled the Yahoo!
protocol. A remote attacker could use this issue to cause Pidgin to crash,
resulting in a denial of service. (CVE-2013-6481)

Fabian Yamaguchi and Christian Wressnegger discovered that Pidgin
incorrectly handled the MSN protocol. A remote attacker could use this
issue to cause Pidgin to crash, resulting in a denial of service.
(CVE-2013-6482)

Fabian Yamaguchi and Christian Wressnegger discovered that Pidgin
incorrectly handled XMPP iq replies. A remote attacker could use this
issue to spoof messages. (CVE-2013-6483)

It was discovered that Pidgin incorrectly handled STUN server responses. A
remote attacker could use this issue to cause Pidgin to crash, resulting in
a denial of service. (CVE-2013-6484)

Matt Jones discovered that Pidgin incorrectly handled certain chunked HTTP
responses. A malicious remote server or a man in the middle could use this
issue to cause Pidgin to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2013-6485)

Yves Younan and Ryan Pentney discovered that Pidgin incorrectly handled
certain Gadu-Gadu HTTP messages. A malicious remote server or a man in the
middle could use this issue to cause Pidgin to crash, resulting in a denial
of service, or possibly execute arbitrary code. (CVE-2013-6487)

Yves Younan and Pawel Janic discovered that Pidgin incorrectly handled MXit
emoticons. A remote attacker could use this issue to cause Pidgin to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2013-6489)

Yves Younan discovered that Pidgin incorrectly handled SIMPLE headers. A
remote attacker could use this issue to cause Pidgin to crash, resulting in
a denial of service, or possibly execute arbitrary code. (CVE ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2100-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|13\.10|12\.10)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.3-0ubuntu1.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.3-0ubuntu1.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.7-0ubuntu4.1.13.10.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.7-0ubuntu4.1.13.10.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.6-0ubuntu2.3", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.6-0ubuntu2.3", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
