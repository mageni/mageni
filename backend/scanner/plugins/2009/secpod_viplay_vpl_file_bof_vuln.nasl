###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_viplay_vpl_file_bof_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# ViPlay .vpl File Stack Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900361");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1660");
  script_bugtraq_id(34877);
  script_name("ViPlay .vpl File Stack Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8644");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50403");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_viplay_detect.nasl");
  script_mandatory_keys("ViPlay/MediaPlayer/Ver");
  script_tag(name:"impact", value:"Attackers may leverage this issue by executing arbitrary codes in
the context of an affected application and cause stack overflow to crash the
application.");
  script_tag(name:"affected", value:"ViPlay3 version 3.0 and prior.");
  script_tag(name:"insight", value:"This flaw is due to improper boundary checks while parsing .vpl files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with ViPlay Media Player and is prone to
  stack overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

viplayVer = get_kb_item("ViPlay/MediaPlayer/Ver");
if(!viplayVer){
  exit(0);
}

if(version_is_less_equal(version:viplayVer, test_version:"3.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
