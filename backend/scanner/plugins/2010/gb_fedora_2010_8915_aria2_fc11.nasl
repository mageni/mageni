###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for aria2 FEDORA-2010-8915
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
tag_insight = "aria2 is a download utility with resuming and segmented downloading.
  Supported protocols are HTTP/HTTPS/FTP/BitTorrent. It also supports Metalink
  version 3.0.

  Currently it has following features:
  - HTTP/HTTPS GET support
  - HTTP Proxy support
  - HTTP BASIC authentication support
  - HTTP Proxy authentication support
  - FTP support(active, passive mode)
  - FTP through HTTP proxy(GET command or tunneling)
  - Segmented download
  - Cookie support
  - It can run as a daemon process.
  - BitTorrent protocol support with fast extension.
  - Selective download in multi-file torrent
  - Metalink version 3.0 support(HTTP/FTP/BitTorrent).
  - Limiting download/upload speed";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "aria2 on Fedora 11";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-May/041758.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313402");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-28 10:00:59 +0200 (Fri, 28 May 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "FEDORA", value: "2010-8915");
  script_cve_id("CVE-2010-1512");
  script_name("Fedora Update for aria2 FEDORA-2010-8915");

  script_tag(name: "summary" , value: "Check for the Version of aria2");
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

  if ((res = isrpmvuln(pkg:"aria2", rpm:"aria2~1.9.3~1.fc11", rls:"FC11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
