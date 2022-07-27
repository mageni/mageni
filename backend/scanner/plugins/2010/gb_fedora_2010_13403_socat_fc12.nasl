###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for socat FEDORA-2010-13403
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
tag_affected = "socat on Fedora 12";
tag_insight = "Socat is a relay for bidirectional data transfer between two independent data
  channels. Each of these data channels may be a file, pipe, device (serial line
  etc. or a pseudo terminal), a socket (UNIX, IP4, IP6 - raw, UDP, TCP), an
  SSL socket, proxy CONNECT connection, a file descriptor (stdin etc.), the GNU
  line editor (readline), a program, or a combination of two of these.
  The compat-readline5 library is used to avoid GPLv2 vs GPLv3 issues.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-September/046681.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313142");
  script_version("$Revision: 8258 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-07 07:38:40 +0200 (Tue, 07 Sep 2010)");
  script_xref(name: "FEDORA", value: "2010-13403");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2799");
  script_name("Fedora Update for socat FEDORA-2010-13403");

  script_tag(name: "summary" , value: "Check for the Version of socat");
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

if(release == "FC12")
{

  if ((res = isrpmvuln(pkg:"socat", rpm:"socat~1.7.1.3~1.fc12", rls:"FC12")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
