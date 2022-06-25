###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avg_av_dos_vuln_lin.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Denial of Service vulnerability in AVG Anti-Virus (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800395");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6662");
  script_bugtraq_id(32749);
  script_name("Denial of Service vulnerability in AVG Anti-Virus (Linux)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47254");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/3461");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_avg_av_detect_lin.nasl");
  script_mandatory_keys("AVG/AV/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code in the
  context of the affected application or even can cause denial of service.");
  script_tag(name:"affected", value:"AVG Anti-Virus version 7.5.51 and prior on Linux.");
  script_tag(name:"insight", value:"The flaw is caused by a memory corruption error when the scan engine processes
  malformed UPX files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with AVG Anti-Virus and is prone to Denial
  of Service Vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}


include("version_func.inc");

avgVer = get_kb_item("AVG/AV/Linux/Ver");
if(!avgVer){
  exit(0);
}

if(version_is_less_equal(version:avgVer, test_version:"7.5.51")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
