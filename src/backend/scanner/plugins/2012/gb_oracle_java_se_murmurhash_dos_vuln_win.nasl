###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_murmurhash_dos_vuln_win.nasl 11549 2018-09-22 12:11:10Z cfischer $
#
# Oracle Java SE 'MurmurHash' Algorithm Hash Collision DoS Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802680");
  script_version("$Revision: 11549 $");
  script_cve_id("CVE-2012-5373");
  script_bugtraq_id(56673);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 14:11:10 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-12-04 14:40:17 +0530 (Tue, 04 Dec 2012)");
  script_name("Oracle Java SE 'MurmurHash' Algorithm Hash Collision DoS Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80299");
  script_xref(name:"URL", value:"http://2012.appsec-forum.ch/conferences/#c17");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2012-001.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=880705");
  script_xref(name:"URL", value:"https://www.131002.net/data/talks/appsec12_slides.pdf");
  script_xref(name:"URL", value:"http://asfws12.files.wordpress.com/2012/11/asfws2012-jean_philippe_aumasson-martin_bosslet-hash_flooding_dos_reloaded.pdf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to cause a denial
of service condition via crafted input to an application that maintains a hash
table.");
  script_tag(name:"affected", value:"Oracle Java SE 7 to 7 Update 4");
  script_tag(name:"insight", value:"The flaw is caused by hash functions based on the 'MurmurHash'
algorithm, which is vulnerable to predictable hash collisions.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Oracle Java SE and is prone to a denial
of service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.4")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
