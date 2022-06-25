###############################################################################
# OpenVAS Vulnerability Test
# $Id: mgasa-2016-0100.nasl 11856 2018-10-12 07:45:29Z cfischer $
#
# Mageia Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2016 Eero Volotinen, http://www.solinor.com
#
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131254");
  script_version("$Revision: 11856 $");
  script_tag(name:"creation_date", value:"2016-03-08 07:15:18 +0200 (Tue, 08 Mar 2016)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:45:29 +0200 (Fri, 12 Oct 2018) $");
  script_name("Mageia Linux Local Check: mgasa-2016-0100");
  script_tag(name:"insight", value:"Updated jasper packages fix security vulnerabilities: The jas_matrix_clip function in jas_seq.c in JasPer 1.900.1 allows remote attackers to cause a denial of service (invalid read and application crash) via a crafted JPEG 2000 image (CVE-2016-2089). Jacob Baines discovered that a double free vulnerability in the jas_iccattrval_destroy function in JasPer 1.900.1 and earlier allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted ICC color profile in a JPEG 2000 image file (CVE-2016-1577). Tyler Hicks discovered that a memory leak in the jas_iccprof_createfrombuf function in JasPer 1.900.1 and earlier allows remote attackers to cause a denial of service (memory consumption) via a crafted ICC color profile in a JPEG 2000 image file (CVE-2016-2116).");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0100.html");
  script_cve_id("CVE-2016-1577", "CVE-2016-2089", "CVE-2016-2116");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Mageia Linux Local Security Checks mgasa-2016-0100");
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
if ((res = isrpmvuln(pkg:"jasper", rpm:"jasper~1.900.1~20.4.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
