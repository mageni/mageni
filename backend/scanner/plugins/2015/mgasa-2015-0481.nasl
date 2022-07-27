###############################################################################
# OpenVAS Vulnerability Test
# $Id: mgasa-2015-0481.nasl 14289 2019-03-18 16:38:27Z cfischer $
#
# Mageia Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131159");
  script_version("$Revision: 14289 $");
  script_tag(name:"creation_date", value:"2015-12-21 14:43:00 +0200 (Mon, 21 Dec 2015)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:38:27 +0100 (Mon, 18 Mar 2019) $");

  script_name("Mageia Linux Local Check: mgasa-2015-0481");

  script_tag(name:"insight", value:"An error in the parsing of incoming responses allows some records with an
incorrect class to be accepted by BIND instead of being rejected as malformed. This can trigger a REQUIRE
assertion failure when those records are subsequently cached. Intentional exploitation of this condition is
possible and could be used as a denial-of-service vector against servers performing recursive queries
(CVE-2015-8000).");

  script_tag(name:"solution", value:"update software");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0481.html");
  script_cve_id("CVE-2015-8000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Mageia Linux Local Security Checks mgasa-2015-0481");
  script_copyright("Eero Volotinen");

  script_family("Mageia Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MAGEIA5")
{
  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.10.3.P2~1.mga5", rls:"MAGEIA5")) != NULL) {
    security_message(data:res);
    exit(0);
}

if (__pkg_match) exit(99);
  exit(0);
}
