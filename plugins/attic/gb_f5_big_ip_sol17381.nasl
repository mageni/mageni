###############################################################################
# OpenVAS Vulnerability Test
#
# F5 BIG-IP - SOL17381 - OpenJDK vulnerability CVE-2014-0428
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105399");
  script_cve_id("CVE-2014-0428");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2020-04-02T11:36:28+0000");

  script_name("F5 BIG-IP - SOL17381 - OpenJDK vulnerability CVE-2014-0428");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/17000/300/sol17381.html");

  script_tag(name:"impact", value:"The vulnerable OpenJDK CORBA component is included, but is not used in supported configurations. A local attacker with access to modify and execute code related to the vulnerable components may be able to breach confidentiality, integrity, and availability of the BIG-IP host.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified vulnerability in Oracle Java SE 5.0u55, 6u65, and 7u45, Java SE Embedded 7u45 and OpenJDK 7 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to CORBA.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2015-10-14 12:11:59 +0200 (Wed, 14 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");

  script_tag(name:"deprecated", value:TRUE); # advisory was changed. no f5 products affected

  exit(0);
}

exit(66);
