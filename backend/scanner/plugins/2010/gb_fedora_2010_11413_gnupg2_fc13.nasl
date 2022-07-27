###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for gnupg2 FEDORA-2010-11413
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
tag_insight = "GnuPG is GNU's tool for secure communication and data storage.  It can
  be used to encrypt data and to create digital signatures.  It includes
  an advanced key management facility and is compliant with the proposed
  OpenPGP Internet standard as described in RFC2440 and the S/MIME
  standard as described by several RFCs.

  GnuPG 2.0 is a newer version of GnuPG with additional support for
  S/MIME.  It has a different design philosophy that splits
  functionality up into several modules. The S/MIME and smartcard functionality
  is provided by the gnupg2-smime package.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "gnupg2 on Fedora 13";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-August/044935.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314064");
  script_version("$Revision: 8266 $");
  script_cve_id("CVE-2010-2547");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-06 10:34:50 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2010-11413");
  script_name("Fedora Update for gnupg2 FEDORA-2010-11413");

  script_tag(name: "summary" , value: "Check for the Version of gnupg2");
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

if(release == "FC13")
{

  if ((res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.0.14~4.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
