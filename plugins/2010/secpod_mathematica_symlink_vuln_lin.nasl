###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mathematica_symlink_vuln_lin.nasl 11553 2018-09-22 14:22:01Z cfischer $
#
# Mathematica Arbitrary File Overwriting Vulnerability (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901117");
  script_version("$Revision: 11553 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2027");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Mathematica Arbitrary File Overwriting Vulnerability (Linux)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_mathematica_detect_lin.nasl");
  script_mandatory_keys("Mathematica/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to create world
writable files in normally restricted directories or corrupt restricted files
via symlink attacks.");
  script_tag(name:"affected", value:"Wolfram Mathematica 7 on Linux.");
  script_tag(name:"insight", value:"The flaw is due to handling of files in the '/tmp/MathLink'
directory in an insecure manner.");
  script_tag(name:"summary", value:"The host is running Mathematica and is prone to arbitrary file
overwriting vulnerability.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39805");
  script_xref(name:"URL", value:"http://marc.info/?l=full-disclosure&m=127380255201760&w=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511298/100/0/threaded");
  exit(0);
}


include("version_func.inc");

mVer = get_kb_item("Mathematica/Ver");
if(!mVer){
  exit(0);
}

if(version_in_range(version:mVer,test_version:"7.0",test_version2:"7.0.1.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
