###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for samba FEDORA-2008-4724
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "samba on Fedora 9";
tag_insight = "Samba is the suite of programs by which a lot of PC-related machines
  share files, printers, and other information (such as lists of
  available files and printers). The Windows NT, OS/2, and Linux
  operating systems support this natively, and add-on packages can
  enable the same thing for DOS, Windows, VMS, UNIX of all kinds, MVS,
  and more. This package provides an SMB/CIFS server that can be used to
  provide network services to SMB/CIFS clients.
  Samba uses NetBIOS over TCP/IP (NetBT) protocols and does NOT
  need the NetBEUI (Microsoft Raw NetBIOS frame) protocol.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-May/msg01030.html");
  script_oid("1.3.6.1.4.1.25623.1.0.310699");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-17 16:47:15 +0100 (Tue, 17 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2008-4724");
  script_cve_id("CVE-2008-1105");
  script_name( "Fedora Update for samba FEDORA-2008-4724");

  script_tag(name:"summary", value:"Check for the Version of samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "FC9")
{

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.2.0~1.rc1.14.fc9", rls:"FC9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}