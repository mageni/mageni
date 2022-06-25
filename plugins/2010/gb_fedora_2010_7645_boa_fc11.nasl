###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for boa FEDORA-2010-7645
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "Boa is a single-tasking HTTP server. That means that unlike traditional web
  servers, it does not fork for each incoming connection, nor does it fork many
  copies of itself to handle multiple connections. It internally multiplexes
  all of the ongoing HTTP connections, and forks only for CGI programs (which
  must be separate processes), automatic directory generation, and automatic
  file gunzipping.
  The primary design goals of Boa are speed and security. Security, in the sense
  of &quot;can't be subverted by a malicious user,&quot; not &quot;fine grained access control
  and encrypted communications&quot;. Boa is not intended as a feature-packed server.

  Available rpmbuild rebuild options :
  --with : debug access poll
  --without : gunzip sendfile";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "boa on Fedora 11";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-May/041274.html");
  script_oid("1.3.6.1.4.1.25623.1.0.315144");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-17 16:00:10 +0200 (Mon, 17 May 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name: "FEDORA", value: "2010-7645");
  script_cve_id("CVE-2009-4496");
  script_name("Fedora Update for boa FEDORA-2010-7645");

  script_tag(name: "summary" , value: "Check for the Version of boa");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC11")
{

  if ((res = isrpmvuln(pkg:"boa", rpm:"boa~0.94.14~0.15.rc21.fc11", rls:"FC11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
