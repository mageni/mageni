###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for OpenSSL HPSBUX02418
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
tag_impact = "Remote unauthorized access";
tag_affected = "OpenSSL on
  HP-UX B.11.11, B.11.23, B.11.31 running OpenSSL";
tag_insight = "A potential security vulnerability has been identified with HP-UX running 
  OpenSSL. The vulnerability could be exploited remotely to allow an 
  unauthorized access.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c01706219-2");
  script_oid("1.3.6.1.4.1.25623.1.0.308708");
  script_version("$Revision: 6584 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 16:13:23 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name: "HPSBUX", value: "02418");
  script_cve_id("CVE-2008-5077");
  script_name( "HP-UX Update for OpenSSL HPSBUX02418");

  script_tag(name:"summary", value:"Check for the Version of OpenSSL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/hp_hp-ux", "ssh/login/release");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-hpux.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "HPUX11.31")
{

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-CONF", revision:"FIPS-OPENSSL-1.1.2.048", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-DOC", revision:"FIPS-OPENSSL-1.1.2.048", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-INC", revision:"FIPS-OPENSSL-1.1.2.048", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-LIB", revision:"FIPS-OPENSSL-1.1.2.048", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-MAN", revision:"FIPS-OPENSSL-1.1.2.048", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-MIS", revision:"FIPS-OPENSSL-1.1.2.048", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-RUN", revision:"FIPS-OPENSSL-1.1.2.048", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-SRC", revision:"FIPS-OPENSSL-1.1.2.048", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-CONF", revision:"FIPS-OPENSSL-1.2.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-DOC", revision:"FIPS-OPENSSL-1.2.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-INC", revision:"FIPS-OPENSSL-1.2.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-LIB", revision:"FIPS-OPENSSL-1.2.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-MAN", revision:"FIPS-OPENSSL-1.2.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-MIS", revision:"FIPS-OPENSSL-1.2.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-RUN", revision:"FIPS-OPENSSL-1.2.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-SRC", revision:"FIPS-OPENSSL-1.2.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CER", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CONF", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-DOC", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-INC", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-LIB", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MAN", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MIS", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PRNG", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PVT", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-RUN", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-SRC", revision:"A.00.09.08j.003", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-CONF", revision:"FIPS-OPENSSL-1.1.2.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-DOC", revision:"FIPS-OPENSSL-1.1.2.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-INC", revision:"FIPS-OPENSSL-1.1.2.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-LIB", revision:"FIPS-OPENSSL-1.1.2.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-MAN", revision:"FIPS-OPENSSL-1.1.2.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-MIS", revision:"FIPS-OPENSSL-1.1.2.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-RUN", revision:"FIPS-OPENSSL-1.1.2.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-SRC", revision:"FIPS-OPENSSL-1.1.2.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-CONF", revision:"FIPS-OPENSSL-1.2.002", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-DOC", revision:"FIPS-OPENSSL-1.2.002", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-INC", revision:"FIPS-OPENSSL-1.2.002", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-LIB", revision:"FIPS-OPENSSL-1.2.002", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-MAN", revision:"FIPS-OPENSSL-1.2.002", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-MIS", revision:"FIPS-OPENSSL-1.2.002", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-RUN", revision:"FIPS-OPENSSL-1.2.002", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-SRC", revision:"FIPS-OPENSSL-1.2.002", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CER", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CONF", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-DOC", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-INC", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-LIB", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MAN", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MIS", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PRNG", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PVT", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-RUN", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-SRC", revision:"A.00.09.07m.047", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-CONF", revision:"FIPS-OPENSSL-1.1.2.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-DOC", revision:"FIPS-OPENSSL-1.1.2.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-INC", revision:"FIPS-OPENSSL-1.1.2.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-LIB", revision:"FIPS-OPENSSL-1.1.2.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-MAN", revision:"FIPS-OPENSSL-1.1.2.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-MIS", revision:"FIPS-OPENSSL-1.1.2.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-RUN", revision:"FIPS-OPENSSL-1.1.2.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_1_2.FIPS-SRC", revision:"FIPS-OPENSSL-1.1.2.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-CONF", revision:"FIPS-OPENSSL-1.2.001", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-DOC", revision:"FIPS-OPENSSL-1.2.001", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-INC", revision:"FIPS-OPENSSL-1.2.001", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-LIB", revision:"FIPS-OPENSSL-1.2.001", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-MAN", revision:"FIPS-OPENSSL-1.2.001", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-MIS", revision:"FIPS-OPENSSL-1.2.001", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-RUN", revision:"FIPS-OPENSSL-1.2.001", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"fips_1_2.FIPS-SRC", revision:"FIPS-OPENSSL-1.2.001", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CER", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CONF", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-DOC", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-INC", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-LIB", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MAN", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MIS", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PRNG", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PVT", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-RUN", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-SRC", revision:"A.00.09.07m.046", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}